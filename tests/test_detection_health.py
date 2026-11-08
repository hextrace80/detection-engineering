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
        response = self.get_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        response = self.post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


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



def resolved_source_response():
    return FakeResponse(200, {"indices": [{"name": "logs-test-000001", "attributes": ["open"]}], "aliases": [], "data_streams": []})


def telemetry_search_response(ingested=None, timestamp=None, ingested_count=0, timestamp_count=0):
    return FakeResponse(200, {
        "timed_out": False,
        "_shards": {"failed": 0},
        "aggregations": {
            "latest_ingested": {"value_as_string": ingested, "value": 1 if ingested else None},
            "latest_timestamp": {"value_as_string": timestamp, "value": 1 if timestamp else None},
            "recent_ingested": {"doc_count": ingested_count},
            "recent_timestamp": {"doc_count": timestamp_count},
        },
    })


class TelemetryAssessmentTests(unittest.TestCase):
    def assess(self, resolve=None, search=None, pattern="logs-test-*"):
        session = FakeSession(
            get_responses=[resolve if resolve is not None else resolved_source_response()],
            post_responses=[search if search is not None else telemetry_search_response()],
        )
        return detection_health.assess_index_pattern(session, "https://es.example", {}, pattern, NOW, 86400), session

    def test_telemetry_uses_event_ingested_and_is_fresh(self):
        assessment, session = self.assess(search=telemetry_search_response(
            ingested="2026-10-18T11:55:00Z", timestamp="2026-10-18T10:00:00Z", ingested_count=12, timestamp_count=99))
        self.assertEqual(assessment["status"], "FRESH")
        self.assertEqual(assessment["timestamp_field"], "event.ingested")
        self.assertEqual(assessment["recent_event_count"], 12)
        self.assertEqual(assessment["assessed_at"], "2026-10-18T12:00:00Z")
        self.assertEqual(assessment["freshness_threshold_seconds"], 86400)
        self.assertEqual(session.get_calls[0][1]["params"], {
            "expand_wildcards": "open", "allow_no_indices": "true", "ignore_unavailable": "true"})
        self.assertEqual(len(session.post_calls), 1)
        self.assertEqual(session.get_calls[0][1]["timeout"], 30)
        self.assertEqual(session.post_calls[0][1]["timeout"], 30)

    def test_stale_ingested_does_not_fall_back_to_fresh_timestamp(self):
        assessment, _ = self.assess(search=telemetry_search_response(
            ingested="2026-10-16T11:55:00Z", timestamp="2026-10-18T11:55:00Z", ingested_count=0, timestamp_count=20))
        self.assertEqual(assessment["status"], "STALE")
        self.assertEqual(assessment["recent_event_count"], 0)

    def test_timestamp_fallback_and_threshold_boundary(self):
        for ingested in (None, "malformed", "2026-10-18T11:55:00"):
            with self.subTest(ingested=ingested):
                assessment, _ = self.assess(search=telemetry_search_response(
                    ingested=ingested, timestamp="2026-10-17T12:00:00Z", timestamp_count=7))
                self.assertEqual(assessment["status"], "FRESH")
                self.assertEqual(assessment["timestamp_field"], "@timestamp")
                self.assertEqual(assessment["recent_event_count"], 7)

    def test_empty_or_invalid_timestamps_are_unknown_with_reliable_count(self):
        for ingested, timestamp in ((None, None), ("invalid", "invalid")):
            with self.subTest(ingested=ingested):
                assessment, _ = self.assess(search=telemetry_search_response(
                    ingested=ingested, timestamp=timestamp, timestamp_count=3))
                self.assertEqual(assessment["status"], "UNKNOWN")
                self.assertIsNone(assessment["last_event_timestamp"])
                self.assertEqual(assessment["recent_event_count"], 3)

    def test_empty_resolution_is_missing_without_search(self):
        assessment, session = self.assess(resolve=FakeResponse(200, {"indices": [], "aliases": [], "data_streams": []}))
        self.assertEqual(assessment["status"], "MISSING")
        self.assertIsNone(assessment["recent_event_count"])
        self.assertEqual(session.post_calls, [])

    def test_explicit_index_not_found_is_missing(self):
        assessment, session = self.assess(resolve=FakeResponse(404, {"error": {"type": "index_not_found_exception"}}))
        self.assertEqual(assessment["status"], "MISSING")
        self.assertEqual(session.post_calls, [])

    def test_alias_and_data_stream_resolution_are_usable(self):
        for kind in ("aliases", "data_streams"):
            with self.subTest(kind=kind):
                payload = {"indices": [], "aliases": [], "data_streams": []}
                payload[kind] = [{"name": "logs-test"}]
                assessment, session = self.assess(resolve=FakeResponse(200, payload), search=telemetry_search_response(ingested="2026-10-18T11:00:00Z"))
                self.assertEqual(assessment["status"], "FRESH")
                self.assertEqual(len(session.post_calls), 1)

    def test_resolve_failures_are_unavailable_and_do_not_leak_details(self):
        for response in (
            FakeResponse(403, {"error": {"type": "index_not_found_exception"}}, text="secret https://private.example"),
            FakeResponse(500, text="secret https://private.example"),
            detection_health.requests.Timeout("secret https://private.example"),
            detection_health.requests.ConnectionError("secret https://private.example"),
            FakeResponse(200, {"indices": []}),
            FakeResponse(200, {"indices": "bad", "aliases": [], "data_streams": []}),
            FakeResponse(200, {"indices": [None], "aliases": [], "data_streams": []}),
            FakeResponse(200, ["invalid"]),
        ):
            with self.subTest(response=response):
                assessment, session = self.assess(resolve=response)
                self.assertEqual(assessment["status"], "UNAVAILABLE")
                self.assertIsNone(assessment["recent_event_count"])
                self.assertEqual(session.post_calls, [])
                self.assertNotIn("secret", json.dumps(assessment))
                self.assertNotIn("https://", json.dumps(assessment))

    def test_search_failures_are_unavailable_without_fabricated_counts(self):
        bad_timeout = telemetry_search_response()
        bad_timeout._payload["timed_out"] = True
        missing_timeout = telemetry_search_response()
        del missing_timeout._payload["timed_out"]
        bad_shards = telemetry_search_response()
        bad_shards._payload["_shards"]["failed"] = 1
        missing_shards = telemetry_search_response()
        del missing_shards._payload["_shards"]
        malformed_count = telemetry_search_response()
        malformed_count._payload["aggregations"]["recent_timestamp"]["doc_count"] = "0"
        for response in (FakeResponse(403, text="secret https://private.example"),
                         detection_health.requests.Timeout("secret https://private.example"),
                         detection_health.requests.ConnectionError("secret https://private.example"),
                         bad_timeout, missing_timeout, bad_shards, missing_shards, malformed_count,
                         FakeResponse(200, {"timed_out": False, "_shards": {"failed": 0}, "aggregations": []}),
                         FakeResponse(200, {"timed_out": False, "_shards": {"failed": 0}, "aggregations": {}})):
            with self.subTest(response=response):
                assessment, _ = self.assess(search=response)
                self.assertEqual(assessment["status"], "UNAVAILABLE")
                self.assertIsNone(assessment["recent_event_count"])
                self.assertNotIn("secret", json.dumps(assessment))
                self.assertNotIn("https://", json.dumps(assessment))

    def test_only_safe_normalized_patterns_are_requested(self):
        self.assertEqual(detection_health.normalize_index_pattern(" LOGS-TEST-* "), "logs-test-*")
        for value in (None, 12, "", "*", "_all", "logs-*,other-*", "remote:logs-*", "logs test", "<logs-{now/d}>", "logs/secret", "logs#secret", "https://secret.example"):
            with self.subTest(value=value):
                self.assertIsNone(detection_health.normalize_index_pattern(value))
                assessment, session = self.assess(pattern=value)
                self.assertEqual(assessment["status"], "NOT_ASSESSED")
                self.assertIsNone(assessment["index_pattern"])
                self.assertEqual(session.get_calls, [])
                self.assertEqual(session.post_calls, [])

    def test_question_wildcard_is_encoded_in_both_paths(self):
        assessment, session = self.assess(pattern="logs-?*")
        self.assertIn("/_resolve/index/logs-%3F*", session.get_calls[0][0])
        self.assertTrue(session.post_calls[0][0].endswith("/logs-%3F*/_search"))

    def test_aggregation_body_is_fixed_and_aggregate_only(self):
        start = NOW - timedelta(days=1)
        body = detection_health.telemetry_aggregation_body(start)
        self.assertEqual(set(body), {"size", "track_total_hits", "aggs"})
        self.assertEqual(body["size"], 0)
        self.assertIs(body["track_total_hits"], False)
        self.assertEqual(body["aggs"], {
            "latest_ingested": {"max": {"field": "event.ingested", "format": "strict_date_optional_time"}},
            "latest_timestamp": {"max": {"field": "@timestamp", "format": "strict_date_optional_time"}},
            "recent_ingested": {"filter": {"range": {"event.ingested": {"gte": "2026-10-17T12:00:00Z"}}}},
            "recent_timestamp": {"filter": {"range": {"@timestamp": {"gte": "2026-10-17T12:00:00Z"}}}},
        })

    def test_threshold_configuration(self):
        self.assertEqual(detection_health.telemetry_freshness_seconds({}), 86400)
        self.assertEqual(detection_health.telemetry_freshness_seconds({"ELASTIC_TELEMETRY_FRESHNESS_SECONDS": "3600"}), 3600)
        for value in ("0", "-1", "not-a-number", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(detection_health.HealthMonitorError, "must be a positive integer"):
                    detection_health.telemetry_freshness_seconds({"ELASTIC_TELEMETRY_FRESHNESS_SECONDS": value})




    def test_unrepresentable_utc_timestamp_uses_fallback_or_remains_unknown(self):
        for ingested in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            for timestamp in ("2026-10-18T11:55:00Z", ingested):
                with self.subTest(ingested=ingested, timestamp=timestamp):
                    assessment, _ = self.assess(search=telemetry_search_response(
                        ingested=ingested, timestamp=timestamp, ingested_count=99, timestamp_count=7))
                    expected = "UNKNOWN" if timestamp == ingested else "FRESH"
                    self.assertEqual(assessment["status"], expected)
                    self.assertEqual(assessment["timestamp_field"], "@timestamp")
                    self.assertEqual(assessment["recent_event_count"], 7)
                    self.assertEqual(assessment["last_event_timestamp"], None if expected == "UNKNOWN" else timestamp)

    def test_threshold_must_fit_the_utc_assessment_window(self):
        largest_window = int((NOW - datetime.min.replace(tzinfo=timezone.utc)).total_seconds())
        with patch.object(detection_health, "datetime", wraps=datetime) as clock:
            clock.now.return_value = NOW
            self.assertEqual(detection_health.telemetry_freshness_seconds({
                "ELASTIC_TELEMETRY_FRESHNESS_SECONDS": str(largest_window)}), largest_window)
            for value in (largest_window + 1, 999999999999999999999):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(detection_health.HealthMonitorError, "representable UTC assessment window"):
                        detection_health.telemetry_freshness_seconds({"ELASTIC_TELEMETRY_FRESHNESS_SECONDS": str(value)})

    def test_unrepresentable_assessment_window_is_rejected_before_resolve(self):
        for value in (int((NOW - datetime.min.replace(tzinfo=timezone.utc)).total_seconds()) + 1, 999999999999999999999):
            with self.subTest(value=value):
                session = FakeSession()
                with self.assertRaisesRegex(detection_health.HealthMonitorError, "representable UTC assessment window"):
                    detection_health.assess_index_pattern(session, "https://es.example", {}, "logs-test-*", NOW, value)
                self.assertEqual(session.get_calls, [])
                self.assertEqual(session.post_calls, [])


class TelemetryCollectionTests(unittest.TestCase):
    def test_reused_index_pattern_is_assessed_once_and_entries_are_retained(self):
        first = dict(rule(), id="first", index=["logs-shared-*", " LOGS-SHARED-* "])
        second = dict(rule(), id="second", index=[" LOGS-SHARED-* "])
        session = FakeSession(get_responses=[resolved_source_response()], post_responses=[
            telemetry_search_response(ingested="2026-10-18T11:55:00Z", ingested_count=12)])
        telemetry = detection_health.collect_rule_telemetry(session, "https://es.example", {}, [first, second], NOW, 86400)
        self.assertEqual(len(session.get_calls), 1)
        self.assertEqual(len(session.post_calls), 1)
        self.assertEqual(len(telemetry["first"]["patterns"]), 2)
        self.assertEqual(telemetry["first"]["patterns"][0], telemetry["second"]["patterns"][0])
        self.assertEqual(telemetry["first"]["status"], "FRESH")

    def test_cache_is_local_to_each_collection_run(self):
        document = dict(rule(), index=["logs-test-*"])
        session = FakeSession(get_responses=[resolved_source_response(), resolved_source_response()], post_responses=[
            telemetry_search_response(ingested="2026-10-18T11:55:00Z"),
            telemetry_search_response(ingested="2026-10-18T11:55:00Z")])
        first = detection_health.collect_rule_telemetry(session, "https://es.example", {}, [document], NOW, 86400)
        later = detection_health.collect_rule_telemetry(session, "https://es.example", {}, [document], NOW + timedelta(days=2), 3600)
        self.assertEqual(len(session.get_calls), 2)
        self.assertEqual(first["rule-uuid"]["status"], "FRESH")
        self.assertEqual(later["rule-uuid"]["status"], "STALE")
        self.assertNotEqual(first["rule-uuid"]["assessed_at"], later["rule-uuid"]["assessed_at"])

    def test_multiple_patterns_preserve_order_and_stale_rollup(self):
        document = dict(rule(), index=["logs-fresh-*", "logs-stale-*"])
        session = FakeSession(get_responses=[resolved_source_response(), resolved_source_response()], post_responses=[
            telemetry_search_response(ingested="2026-10-18T11:55:00Z"),
            telemetry_search_response(ingested="2026-10-16T00:00:00Z")])
        assessment = detection_health.collect_rule_telemetry(session, "https://es.example", {}, [document], NOW, 86400)["rule-uuid"]
        self.assertEqual(assessment["status"], "STALE")
        self.assertEqual([item["index_pattern"] for item in assessment["patterns"]], ["logs-fresh-*", "logs-stale-*"])
        self.assertEqual([item["status"] for item in assessment["patterns"]], ["FRESH", "STALE"])
        self.assertEqual({item["assessed_at"] for item in assessment["patterns"]}, {assessment["assessed_at"]})

    def test_rollup_precedence(self):
        for statuses, expected in (
            (["FRESH", "UNKNOWN", "STALE", "MISSING", "UNAVAILABLE"], "UNAVAILABLE"),
            (["FRESH", "UNKNOWN", "STALE", "MISSING"], "MISSING"),
            (["FRESH", "UNKNOWN", "STALE"], "STALE"),
            (["FRESH", "UNKNOWN"], "UNKNOWN"),
            (["FRESH", "FRESH"], "FRESH"),
            (["FRESH", "NOT_ASSESSED"], "NOT_ASSESSED"),
            ([], "NOT_ASSESSED"),
        ):
            with self.subTest(statuses=statuses):
                patterns = [{"status": status} for status in statuses]
                rolled = detection_health.telemetry_rollup(patterns, NOW, 86400)
                self.assertEqual(rolled, {"status": expected, "assessed_at": "2026-10-18T12:00:00Z", "freshness_threshold_seconds": 86400, "patterns": patterns})

    def test_missing_or_invalid_index_list_is_not_assessed(self):
        for index in (None, [], "logs-test-*", {"pattern": "logs-test-*"}):
            with self.subTest(index=index):
                document = rule() if index is None else dict(rule(), index=index)
                session = FakeSession()
                result = detection_health.collect_rule_telemetry(session, "https://es.example", {}, [document], NOW, 86400)
                self.assertEqual(result["rule-uuid"]["status"], "NOT_ASSESSED")
                self.assertEqual(result["rule-uuid"]["patterns"], [])
                self.assertEqual(session.get_calls, [])
                self.assertEqual(session.post_calls, [])

    def test_rejected_pattern_is_retained_without_publishing_original_input(self):
        document = dict(rule(), index=["logs-test-*", "https://private.example/secret", None])
        session = FakeSession(get_responses=[resolved_source_response()], post_responses=[telemetry_search_response(ingested="2026-10-18T11:55:00Z")])
        result = detection_health.collect_rule_telemetry(session, "https://es.example", {}, [document], NOW, 86400)["rule-uuid"]
        self.assertEqual(result["status"], "NOT_ASSESSED")
        self.assertEqual(len(result["patterns"]), 3)
        self.assertEqual([item["status"] for item in result["patterns"]], ["FRESH", "NOT_ASSESSED", "NOT_ASSESSED"])
        self.assertNotIn("private.example", json.dumps(result))
        self.assertEqual(len(session.get_calls), 1)

    def test_rows_attach_telemetry_without_changing_execution_or_alert_metrics(self):
        baseline = detection_health.build_rows([rule()], {}, None, NOW, 900, 3)
        baseline_metrics = detection_health.summary_metrics(baseline)
        for status in ("FRESH", "STALE", "MISSING", "UNAVAILABLE", "UNKNOWN", "NOT_ASSESSED"):
            with self.subTest(status=status):
                telemetry = detection_health.telemetry_rollup([{"status": status}], NOW, 86400)
                rows = detection_health.build_rows([rule()], {}, None, NOW, 900, 3, {"rule-uuid": telemetry})
                self.assertEqual(rows[0]["telemetry"], telemetry)
                self.assertEqual(rows[0]["status"], "HEALTHY")
                self.assertIsNone(rows[0]["alert_activity"])
                self.assertEqual(detection_health.summary_metrics(rows)["total_alerts"], baseline_metrics["total_alerts"])
                self.assertEqual(detection_health.summary_metrics(rows)["healthy_enabled"], baseline_metrics["healthy_enabled"])
                flags = [flag for flag in rows[0]["review_flags"] if flag.startswith("TELEMETRY_")]
                self.assertEqual(flags, [f"TELEMETRY_{status}"] if status in {"STALE", "MISSING", "UNAVAILABLE", "UNKNOWN"} else [])
                snapshot = detection_health.health_snapshot(rows, "now-30d", NOW)
                self.assertEqual(snapshot["schema_version"], 1)
                self.assertEqual(snapshot["inventory"][0]["telemetry"], telemetry)
        self.assertEqual(baseline[0]["telemetry"], {"status": "NOT_ASSESSED", "assessed_at": None, "freshness_threshold_seconds": None, "patterns": []})
        missing_mapping = detection_health.build_rows([rule()], {}, None, NOW, 900, 3, {})
        self.assertEqual(missing_mapping[0]["telemetry"], baseline[0]["telemetry"])
        self.assertEqual(next(csv.reader(io.StringIO(detection_health.inventory_csv(baseline, NOW))))[-1], "Review flags")

    def test_required_environment_validates_telemetry_threshold(self):
        configured = {"ELASTIC_HEALTH_KEY": "mock-key", "ELASTIC_KIBANA_URL": "https://kb.example", "ELASTICSEARCH_URL": "https://es.example"}
        with patch.dict(os.environ, configured, clear=True):
            self.assertEqual(detection_health.required_environment()["telemetry_freshness_seconds"], 86400)
        for value in ("3600", "0", "-1", "not-a-number"):
            with self.subTest(value=value), patch.dict(os.environ, dict(configured, ELASTIC_TELEMETRY_FRESHNESS_SECONDS=value), clear=True):
                if value == "3600":
                    self.assertEqual(detection_health.required_environment()["telemetry_freshness_seconds"], 3600)
                else:
                    with self.assertRaisesRegex(detection_health.HealthMonitorError, "must be a positive integer"):
                        detection_health.required_environment()

    def test_main_writes_reports_even_when_telemetry_is_unavailable(self):
        document = dict(rule(), index=["logs-test-*"])
        session = FakeSession(
            get_responses=[FakeResponse(200, {"data": [document], "total": 1}), FakeResponse(403, text="secret")],
            post_responses=[FakeResponse(200, {"timed_out": False, "_shards": {"failed": 0}, "aggregations": {"rules": {"buckets": []}}})])
        config = {"api_key": "mock-key", "kibana_url": "https://kb.example", "elasticsearch_url": "https://es.example", "space": "default", "lookback": "now-30d", "stale_after": 900, "interval_multiplier": 3, "telemetry_freshness_seconds": 86400}
        with patch.object(detection_health, "required_environment", return_value=config), patch.object(detection_health.requests, "Session", return_value=session), patch.object(detection_health, "write_audit_reports", return_value=("csv", "md", "json")) as writer, patch("builtins.print"):
            self.assertEqual(detection_health.main(), 0)
        rows, _, generated_at = writer.call_args.args
        self.assertEqual(rows[0]["telemetry"]["status"], "UNAVAILABLE")
        self.assertEqual(rows[0]["telemetry"]["assessed_at"], detection_health.generation_timestamp(generated_at))
        self.assertIsNone(rows[0]["alert_error"])
        self.assertIsNone(rows[0]["telemetry"]["patterns"][0]["recent_event_count"])

    def test_main_does_not_overwrite_reports_when_alerts_are_unavailable(self):
        session = FakeSession(get_responses=[FakeResponse(200, {"data": [dict(rule(), index=["logs-test-*"])], "total": 1})], post_responses=[FakeResponse(403, text="unavailable")])
        config = {"api_key": "mock-key", "kibana_url": "https://kb.example", "elasticsearch_url": "https://es.example", "space": "default", "lookback": "now-30d", "stale_after": 900, "interval_multiplier": 3, "telemetry_freshness_seconds": 86400}
        with patch.object(detection_health, "required_environment", return_value=config), patch.object(detection_health.requests, "Session", return_value=session), patch.object(detection_health, "collect_rule_telemetry") as collector, patch.object(detection_health, "write_audit_reports") as writer, patch("builtins.print"):
            self.assertEqual(detection_health.main(), 1)
        collector.assert_not_called()
        writer.assert_not_called()



    def test_main_writes_reports_after_unrepresentable_utc_maxima(self):
        documents = [dict(rule(), id="fallback", index=["logs-fallback-*"]), dict(rule(), id="unknown", index=["logs-unknown-*"])]
        session = FakeSession(
            get_responses=[FakeResponse(200, {"data": documents, "total": 2}), resolved_source_response(), resolved_source_response()],
            post_responses=[
                FakeResponse(200, {"timed_out": False, "_shards": {"failed": 0}, "aggregations": {"rules": {"buckets": []}}}),
                telemetry_search_response(ingested="0001-01-01T00:00:00+01:00", timestamp="2026-10-18T11:55:00Z", timestamp_count=7),
                telemetry_search_response(ingested="9999-12-31T23:59:59-01:00", timestamp="0001-01-01T00:00:00+01:00", timestamp_count=3),
            ])
        config = {"api_key": "mock-key", "kibana_url": "https://kb.example", "elasticsearch_url": "https://es.example", "space": "default", "lookback": "now-30d", "stale_after": 900, "interval_multiplier": 3, "telemetry_freshness_seconds": 86400}
        real_writer = detection_health.write_audit_reports
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports = Path(temporary_directory)
            with patch.object(detection_health, "required_environment", return_value=config), patch.object(detection_health.requests, "Session", return_value=session), patch.object(detection_health, "datetime", wraps=datetime) as clock, patch.object(detection_health, "write_audit_reports", side_effect=lambda rows, lookback, generated_at: real_writer(rows, lookback, generated_at, reports)), patch("builtins.print"):
                clock.now.return_value = NOW
                self.assertEqual(detection_health.main(), 0)
            snapshot = json.loads((reports / detection_health.SNAPSHOT_REPORT_NAME).read_text(encoding="utf-8"))
            by_id = {row["uuid"]: row for row in snapshot["inventory"]}
            self.assertEqual(by_id["fallback"]["telemetry"]["status"], "FRESH")
            self.assertEqual(by_id["fallback"]["telemetry"]["patterns"][0]["last_event_timestamp"], "2026-10-18T11:55:00Z")
            self.assertEqual(by_id["unknown"]["telemetry"]["status"], "UNKNOWN")
            self.assertIsNone(by_id["unknown"]["telemetry"]["patterns"][0]["last_event_timestamp"])
            self.assertEqual(by_id["unknown"]["telemetry"]["patterns"][0]["recent_event_count"], 3)
            self.assertTrue((reports / detection_health.INVENTORY_REPORT_NAME).is_file())
            self.assertTrue((reports / detection_health.SUMMARY_REPORT_NAME).is_file())

    def test_main_rejects_unrepresentable_threshold_before_creating_session(self):
        configured = {"ELASTIC_HEALTH_KEY": "mock-key", "ELASTIC_KIBANA_URL": "https://kb.example", "ELASTICSEARCH_URL": "https://es.example"}
        largest_window = int((NOW - datetime.min.replace(tzinfo=timezone.utc)).total_seconds())
        for value in (largest_window + 1, 999999999999999999999):
            with self.subTest(value=value), patch.dict(os.environ, dict(configured, ELASTIC_TELEMETRY_FRESHNESS_SECONDS=str(value)), clear=True), patch.object(detection_health, "datetime", wraps=datetime) as clock, patch.object(detection_health.requests, "Session") as session_factory, patch("builtins.print") as output:
                clock.now.return_value = NOW
                self.assertEqual(detection_health.main(), 1)
                session_factory.assert_not_called()
                self.assertIn("representable UTC assessment window", output.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
