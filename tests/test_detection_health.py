"""Mocked tests for the read-only Elastic detection health monitor."""

import csv
import importlib.util
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


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

    def test_required_environment_uses_caller_configuration_without_overwriting_it(self):
        configured = {
            "ELASTIC_HEALTH_KEY": "read-only-test-key",
            "ELASTIC_KIBANA_URL": "https://kibana.example.test",
            "ELASTICSEARCH_URL": "https://elasticsearch.example.test",
            "ELASTIC_SECURITY_SPACE": "security-lab",
        }
        with patch.dict(os.environ, configured, clear=True):
            settings = detection_health.required_environment()

        self.assertEqual(settings["kibana_url"], "https://kibana.example.test")
        self.assertEqual(settings["elasticsearch_url"], "https://elasticsearch.example.test")
        self.assertEqual(settings["space"], "security-lab")

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

    def test_inventory_csv_preserves_full_names_and_uses_snapshot_timestamp(self):
        full_name = "A long rule name that must not be truncated in the CSV inventory"
        document = rule()
        document.update({"name": full_name, "type": "query", "interval": "5m"})
        rows = detection_health.build_rows(
            [document],
            {"rule-uuid": {"count": 3, "last_alert": "2026-10-18T11:00:00Z"}},
            None,
            NOW,
            900,
            3,
        )

        content = detection_health.inventory_csv(rows, NOW)
        record = next(csv.DictReader(io.StringIO(content)))

        self.assertEqual(record["Report generation timestamp"], "2026-10-18T12:00:00Z")
        self.assertEqual(record["Rule name"], full_name)
        self.assertEqual(record["Elastic internal UUID"], "rule-uuid")
        self.assertEqual(record["Alert count for selected lookback"], "3")
        self.assertEqual(record["Most recent alert timestamp"], "2026-10-18T11:00:00Z")

    def test_markdown_summary_calculates_metrics_and_duplicate_candidates(self):
        healthy = rule()
        healthy.update({"name": "Repeated   Name", "type": "query"})
        failed = rule(execution_status="failed")
        failed.update({"id": "rule-uuid-2", "rule_id": "stable-rule-id-2", "name": "repeated name", "type": "query"})
        disabled = rule(enabled=False)
        disabled.update({"id": "rule-uuid-3", "rule_id": "stable-rule-id-3", "name": "Disabled rule", "type": "query"})
        rows = detection_health.build_rows(
            [healthy, failed, disabled],
            {"rule-uuid": {"count": 4, "last_alert": "2026-10-18T11:00:00Z"}},
            None,
            NOW,
            900,
            3,
        )

        summary = detection_health.markdown_summary(rows, "now-30d", NOW)

        self.assertIn("Generated: 2026-10-18T12:00:00Z", summary)
        self.assertIn("| Total deployed rules | 3 |", summary)
        self.assertIn("| Enabled | 2 |", summary)
        self.assertIn("| Disabled | 1 |", summary)
        self.assertIn("| Healthy | 1 |", summary)
        self.assertIn("| Failed | 1 |", summary)
        self.assertIn("Operational health rate: **50.0%** (1 HEALTHY enabled rules / 2 enabled rules).", summary)
        self.assertIn("Enabled rules with one or more recorded alerts: **1 of 2 (50.0%)**.", summary)
        self.assertIn("Total alerts in selected lookback: **4**.", summary)
        self.assertIn("Candidate: **Repeated   Name**", summary)
        self.assertIn("`rule-uuid`", summary)
        self.assertIn("`rule-uuid-2`", summary)

    def test_missing_alert_data_does_not_overwrite_existing_reports(self):
        rows = detection_health.build_rows([rule()], None, "HTTP 500", NOW, 900, 3)
        self.assertEqual(detection_health.alert_fields(rows[0]), ("UNAVAILABLE", "UNAVAILABLE"))
        self.assertIn("Alert activity: **UNAVAILABLE**", detection_health.markdown_summary(rows, "now-30d", NOW))
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports_directory = Path(temporary_directory)
            inventory = reports_directory / detection_health.INVENTORY_REPORT_NAME
            summary = reports_directory / detection_health.SUMMARY_REPORT_NAME
            inventory.write_text("complete inventory", encoding="utf-8")
            summary.write_text("complete summary", encoding="utf-8")

            with self.assertRaisesRegex(detection_health.HealthMonitorError, "not written"):
                detection_health.write_audit_reports(rows, "now-30d", NOW, reports_directory)

            self.assertEqual(inventory.read_text(encoding="utf-8"), "complete inventory")
            self.assertEqual(summary.read_text(encoding="utf-8"), "complete summary")

    def test_health_snapshot_preserves_metrics_and_unavailable_alerts(self):
        rows = detection_health.build_rows([rule()], None, "HTTP 500", NOW, 900, 3)

        snapshot = detection_health.health_snapshot(rows, "now-30d", NOW)

        self.assertEqual(snapshot["schema_version"], 1)
        self.assertEqual(snapshot["generated_at"], "2026-10-18T12:00:00Z")
        self.assertEqual(snapshot["lookback"], "now-30d")
        self.assertFalse(snapshot["collection"]["alert_activity_available"])
        self.assertEqual(snapshot["collection"]["alert_activity_status"], "unavailable")
        self.assertIsNone(snapshot["metrics"]["total_alerts"])
        self.assertEqual(snapshot["inventory"][0]["alert_error"], "HTTP 500")

    def test_audit_reports_write_csv_markdown_and_json_from_one_snapshot(self):
        document = rule()
        document.update({"name": "Audit rule", "type": "query"})
        rows = detection_health.build_rows(
            [document],
            {"rule-uuid": {"count": 2, "last_alert": "2026-10-18T11:00:00Z"}},
            None,
            NOW,
            900,
            3,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            inventory, summary, snapshot = detection_health.write_audit_reports(
                rows, "now-30d", NOW, Path(temporary_directory)
            )
            inventory_record = next(csv.DictReader(io.StringIO(inventory.read_text(encoding="utf-8"))))
            summary_text = summary.read_text(encoding="utf-8")
            snapshot_document = json.loads(snapshot.read_text(encoding="utf-8"))

        self.assertEqual(inventory_record["Report generation timestamp"], "2026-10-18T12:00:00Z")
        self.assertEqual(inventory_record["Alert count for selected lookback"], "2")
        self.assertIn("Generated: 2026-10-18T12:00:00Z", summary_text)
        self.assertIn("Total alerts in selected lookback: **2**.", summary_text)
        self.assertEqual(snapshot_document["generated_at"], "2026-10-18T12:00:00Z")
        self.assertEqual(snapshot_document["inventory"][0]["uuid"], "rule-uuid")


if __name__ == "__main__":
    unittest.main()
