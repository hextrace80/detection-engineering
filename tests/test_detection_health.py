"""Mocked tests for the read-only Elastic detection health monitor."""

import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "detection_health.py"
SPEC = importlib.util.spec_from_file_location("detection_health", SCRIPT_PATH)
detection_health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(detection_health)


class FakeResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, get_responses=None, post_responses=None):
        self.get_responses = list(get_responses or [])
        self.post_responses = list(post_responses or [])
        self.get_calls = []
        self.post_calls = []

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return self.get_responses.pop(0)

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        return self.post_responses.pop(0)


NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


def rule(enabled=True, execution_status="succeeded", execution_time=None, interval="5m"):
    document = {"id": "rule-uuid", "rule_id": "stable-rule-id", "name": "Test rule", "enabled": enabled, "interval": interval}
    if execution_status is not None:
        execution_time = execution_time or NOW
        document["execution_summary"] = {
            "last_execution": {"status": execution_status, "date": execution_time.isoformat().replace("+00:00", "Z")}
        }
    return document


class DetectionHealthTests(unittest.TestCase):
    def classify(self, document):
        return detection_health.classify_rule(document, NOW, 900, 3)

    def test_disabled_rule_is_not_stale(self):
        self.assertEqual(self.classify(rule(enabled=False, execution_time=NOW - timedelta(days=1))), "DISABLED")

    def test_failed_rule_is_failed(self):
        self.assertEqual(self.classify(rule(execution_status="failed")), "FAILED")

    def test_partial_failure_rule_is_degraded(self):
        self.assertEqual(self.classify(rule(execution_status="partial failure")), "DEGRADED")

    def test_successful_recent_rule_is_healthy(self):
        self.assertEqual(self.classify(rule(execution_time=NOW - timedelta(minutes=5))), "HEALTHY")

    def test_successful_overdue_rule_is_stale_using_interval(self):
        self.assertEqual(self.classify(rule(execution_time=NOW - timedelta(minutes=16))), "STALE")

    def test_rule_without_execution_data_is_not_yet_executed(self):
        self.assertEqual(self.classify(rule(execution_status=None)), "NOT_YET_EXECUTED")

    def test_non_dictionary_execution_summaries_are_safe(self):
        for execution_summary in (None, [], "not an object"):
            with self.subTest(execution_summary=execution_summary):
                document = rule()
                document["execution_summary"] = execution_summary
                self.assertEqual(self.classify(document), "NOT_YET_EXECUTED")

                rows = detection_health.build_rows([document], {}, None, NOW, 900, 3)
                self.assertEqual(rows[0]["execution"], {})

    def test_unrecognized_execution_status_is_unknown(self):
        self.assertEqual(self.classify(rule(execution_status="running")), "UNKNOWN")

    def test_rule_pagination_collects_all_rules(self):
        session = FakeSession(
            get_responses=[
                FakeResponse(200, {"data": [rule()], "total": 2}),
                FakeResponse(200, {"data": [dict(rule(), id="rule-uuid-2")], "total": 2}),
            ]
        )
        rules = detection_health.get_rules(session, "https://kb.example", "default", {})

        self.assertEqual(len(rules), 2)
        self.assertEqual([call[1]["params"]["page"] for call in session.get_calls], [1, 2])

    def test_rule_without_usable_id_is_rejected_before_alert_correlation(self):
        invalid_rule = rule()
        invalid_rule["id"] = None
        session = FakeSession(get_responses=[FakeResponse(200, {"data": [invalid_rule], "total": 1})])

        with self.assertRaisesRegex(detection_health.HealthMonitorError, "no usable id"):
            detection_health.get_rules(session, "https://kb.example", "default", {})

    def test_alert_composite_pagination_collects_all_buckets(self):
        session = FakeSession(
            post_responses=[
                FakeResponse(
                    200,
                    {"timed_out": False, "_shards": {"failed": 0}, "aggregations": {"rules": {"buckets": [{"key": {"rule_uuid": "rule-uuid"}, "doc_count": 2, "last_alert": {"value_as_string": "2026-10-18T11:00:00Z"}}], "after_key": {"rule_uuid": "rule-uuid"}}}},
                ),
                FakeResponse(
                    200,
                    {"timed_out": False, "_shards": {"failed": 0}, "aggregations": {"rules": {"buckets": [{"key": {"rule_uuid": "rule-uuid-2"}, "doc_count": 1, "last_alert": {"value_as_string": "2026-10-18T10:00:00Z"}}]}}},
                ),
            ]
        )
        activity = detection_health.get_alert_activity(session, "https://es.example", "default", {}, "now-30d")

        self.assertEqual(set(activity), {"rule-uuid", "rule-uuid-2"})
        self.assertEqual(len(session.post_calls), 2)
        self.assertEqual(session.post_calls[1][1]["json"]["aggs"]["rules"]["composite"]["after"], {"rule_uuid": "rule-uuid"})

    def test_timed_out_alert_search_is_unavailable(self):
        session = FakeSession(post_responses=[FakeResponse(200, {"timed_out": True})])

        with self.assertRaisesRegex(detection_health.HealthMonitorError, "search timed out"):
            detection_health.get_alert_activity(session, "https://es.example", "default", {}, "now-30d")

    def test_shard_failed_alert_search_is_unavailable(self):
        session = FakeSession(post_responses=[FakeResponse(200, {"timed_out": False, "_shards": {"failed": 1}})])

        with self.assertRaisesRegex(detection_health.HealthMonitorError, "shard failures"):
            detection_health.get_alert_activity(session, "https://es.example", "default", {}, "now-30d")

    def test_alert_api_failure_is_reported_as_unavailable_not_zero(self):
        session = FakeSession(post_responses=[FakeResponse(500, text="server error")])
        with self.assertRaisesRegex(detection_health.HealthMonitorError, "HTTP 500"):
            detection_health.get_alert_activity(session, "https://es.example", "default", {}, "now-30d")

        rows = detection_health.build_rows([rule()], None, "HTTP 500", NOW, 900, 3)
        self.assertEqual(detection_health.alert_text(rows[0], "now-30d"), "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
