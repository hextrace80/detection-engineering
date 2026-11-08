"""Offline tests for the static Detection Health Dashboard generator."""

import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "build_detection_health_dashboard.py"
SPEC = importlib.util.spec_from_file_location("detection_health_dashboard", SCRIPT_PATH)
dashboard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard)


TIMESTAMP = "2026-10-19T03:19:56.004046Z"
CSV_FIELDS = [
    "Report generation timestamp",
    "Rule name",
    "Stable rule_id",
    "Elastic internal UUID",
    "Enabled state",
    "Health classification",
    "Rule type",
    "Execution interval",
    "Last execution time",
    "Last execution status",
    "Alert count for selected lookback",
    "Most recent alert timestamp",
    "Review flags",
]


def legacy_record(**changes):
    record = {
        "Report generation timestamp": TIMESTAMP,
        "Rule name": "Repository rule",
        "Stable rule_id": "stable-rule-id",
        "Elastic internal UUID": "elastic-uuid-1",
        "Enabled state": "enabled",
        "Health classification": "HEALTHY",
        "Rule type": "query",
        "Execution interval": "5m",
        "Last execution time": "2026-10-19T03:17:35.734Z",
        "Last execution status": "succeeded",
        "Alert count for selected lookback": "2",
        "Most recent alert timestamp": "2026-10-18T11:00:00Z",
        "Review flags": "",
    }
    record.update(changes)
    return record


def write_legacy_reports(directory, records):
    csv_path = directory / "detection_health_inventory.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(records)
    markdown_path = directory / "detection_health_summary.md"
    markdown_path.write_text(
        f"# Detection Health & Metrics Audit Report\n\nGenerated: {TIMESTAMP}\nAlert lookback: `now-30d`\n",
        encoding="utf-8",
    )
    return csv_path, markdown_path


def write_detection(directory, name="Repository rule", rule_id="stable-rule-id", description="Description"):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "repository_rule.toml"
    path.write_text(
        "\n".join(
            [
                "[rule]",
                f'name = "{name}"',
                f'description = "{description}"',
                f'rule_id = "{rule_id}"',
                'severity = "medium"',
                "risk_score = 47",
                'type = "query"',
                'index = ["logs-test-*"]',
                "",
                "[[rule.threat]]",
                'framework = "MITRE ATT&CK"',
                "[[rule.threat.technique]]",
                'id = "T1098"',
                'name = "Account Manipulation"',
            ]
        ),
        encoding="utf-8",
    )
    return path


def telemetry_snapshot(status="STALE"):
    return {
        "schema_version": 1,
        "generated_at": TIMESTAMP,
        "lookback": "now-30d",
        "collection": {"source_kind": "elastic_live", "is_live": True},
        "inventory": [{
            "name": "Telemetry rule", "rule_id": "stable-rule-id", "uuid": "uuid-1",
            "enabled": True, "type": "query", "interval": "5m", "status": "HEALTHY",
            "execution": {"status": "succeeded"},
            "alert_activity": {"count": 2, "last_alert": TIMESTAMP},
            "alert_error": None, "review_flags": [],
            "telemetry": {
                "status": status, "assessed_at": TIMESTAMP,
                "freshness_threshold_seconds": 86400,
                "patterns": [{
                    "index_pattern": "logs-windows.sysmon_operational-*", "status": status,
                    "timestamp_field": "event.ingested",
                    "last_event_timestamp": "2026-10-17T00:00:00Z", "recent_event_count": 0,
                }],
            },
        }],
    }


class DetectionHealthDashboardTests(unittest.TestCase):
    def test_telemetry_is_preserved_independently_from_execution_and_alerts(self):
        snapshot = telemetry_snapshot()
        model = dashboard.dashboard_model(snapshot, [])
        row = model["rows"][0]

        self.assertEqual(row["telemetry_health"]["status"], "STALE")
        self.assertEqual(row["telemetry_health"]["assessed_at"], TIMESTAMP)
        self.assertEqual(row["telemetry_health"]["freshness_threshold_seconds"], 86400)
        self.assertEqual(row["telemetry_health"]["patterns"], snapshot["inventory"][0]["telemetry"]["patterns"])
        self.assertEqual(row["operational_health"]["status"], "HEALTHY")
        self.assertEqual(row["alert_activity"]["count"], 2)
        self.assertEqual(model["summary"]["statuses"]["HEALTHY"], 1)
        self.assertEqual(model["summary"]["statuses"]["STALE"], 0)
        self.assertEqual(model["review_sections"]["execution_concerns"], [])
        self.assertEqual(model["review_sections"]["telemetry_concerns"], [row])

    def test_telemetry_concern_queue_contains_only_assessed_concerns(self):
        for status in ("FRESH", "STALE", "MISSING", "UNAVAILABLE", "UNKNOWN", "NOT_ASSESSED"):
            with self.subTest(status=status):
                model = dashboard.dashboard_model(telemetry_snapshot(status), [])
                self.assertEqual(model["rows"][0]["telemetry_health"]["status"], status)
                self.assertEqual(
                    bool(model["review_sections"]["telemetry_concerns"]),
                    status in {"STALE", "MISSING", "UNAVAILABLE", "UNKNOWN"},
                )

    def test_historical_snapshot_does_not_infer_telemetry(self):
        snapshot = telemetry_snapshot()
        snapshot["collection"] = {"source_kind": "legacy_report_snapshot", "is_live": False}
        del snapshot["inventory"][0]["telemetry"]
        model = dashboard.dashboard_model(snapshot, [])
        telemetry = model["rows"][0]["telemetry_health"]

        self.assertEqual(telemetry["status"], "NOT_ASSESSED")
        self.assertIsNone(telemetry["assessed_at"])
        self.assertIsNone(telemetry["freshness_threshold_seconds"])
        self.assertEqual(telemetry["patterns"], [])
        self.assertIn("not assessed", telemetry["note"])
        self.assertEqual(model["review_sections"]["telemetry_concerns"], [])

    def test_telemetry_defaults_for_repository_only_and_malformed_optional_data(self):
        for invalid in (None, [], "STALE"):
            with self.subTest(invalid=invalid):
                self.assertEqual(
                    dashboard.display_row({"telemetry": invalid})["telemetry_health"]["status"],
                    "NOT_ASSESSED",
                )
        self.assertEqual(dashboard.display_row(None)["telemetry_health"]["status"], "NOT_ASSESSED")
        row = dashboard.display_row({"telemetry": {"status": [], "patterns": [None, "invalid"]}})
        self.assertEqual(row["telemetry_health"]["status"], "UNKNOWN")
        self.assertEqual(row["telemetry_health"]["patterns"], [])
        row = dashboard.display_row({"telemetry": {"patterns": "invalid"}})
        self.assertEqual(row["telemetry_health"]["patterns"], [])

    def test_telemetry_metadata_is_safely_embedded_and_rendered_as_text(self):
        snapshot = telemetry_snapshot()
        payload = '</script><script>alert("telemetry")</script>&'
        telemetry = snapshot["inventory"][0]["telemetry"]
        telemetry["assessed_at"] = payload
        for key in ("index_pattern", "timestamp_field", "last_event_timestamp"):
            telemetry["patterns"][0][key] = payload
        model = dashboard.dashboard_model(snapshot, [])
        html = dashboard.dashboard_html(model)
        javascript = dashboard.DASHBOARD_JS_CONTENT

        self.assertNotIn(payload, html)
        embedded = html.split('<script id="dashboard-data" type="application/json">', 1)[1].split("</script>", 1)[0]
        self.assertNotIn("<", embedded)
        self.assertNotIn(">", embedded)
        self.assertNotIn("&", embedded)
        self.assertEqual(json.loads(embedded)["rows"][0]["telemetry_health"]["patterns"][0]["index_pattern"], payload)
        self.assertIn("node.textContent =", javascript)
        self.assertIn("[row.telemetry_health.status]", javascript)
        self.assertIn('field("Telemetry status",', javascript)
        self.assertIn('field("Telemetry assessment time",', javascript)
        self.assertIn('field("Telemetry threshold seconds",', javascript)
        self.assertIn('field("Telemetry patterns",', javascript)
        self.assertIn("row.telemetry_health.patterns", javascript)
        for key in ("index_pattern", "status", "timestamp_field", "last_event_timestamp", "recent_event_count"):
            self.assertIn(f"pattern.{key}", javascript)
        self.assertIn('text(line,', javascript)
        self.assertIn('reviewList("Telemetry freshness concerns", model.review_sections.telemetry_concerns', javascript)
        self.assertIn("<th>Telemetry</th>", html)
        self.assertNotIn("innerHTML", javascript)
        self.assertNotIn(".href", javascript)
        self.assertTrue(any("configurable ingestion-availability heuristic" in note for note in model["limitations"]))

    def test_legacy_reports_convert_to_explicit_historical_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(directory, [legacy_record()])
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)

        self.assertEqual(snapshot["schema_version"], 1)
        self.assertEqual(snapshot["generated_at"], TIMESTAMP)
        self.assertFalse(snapshot["collection"]["is_live"])
        self.assertEqual(snapshot["collection"]["source_kind"], "legacy_report_snapshot")
        self.assertEqual(snapshot["metrics"]["total_alerts"], 2)

    def test_unavailable_alert_data_remains_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(
                directory,
                [legacy_record(**{"Alert count for selected lookback": "UNAVAILABLE"})],
            )
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)

        self.assertFalse(snapshot["metrics"]["alert_available"])
        self.assertIsNone(snapshot["metrics"]["total_alerts"])
        self.assertIsNotNone(snapshot["inventory"][0]["alert_error"])

    def test_stable_rule_id_matches_even_when_names_differ(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(
                directory,
                [legacy_record(**{"Rule name": "Elastic renamed rule"})],
            )
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)
            detection_directory = directory / "detections"
            write_detection(detection_directory, name="Repository rule")
            repository_rules = dashboard.load_repository_rules(detection_directory)
            model = dashboard.dashboard_model(snapshot, repository_rules)

        self.assertEqual(len(model["rows"]), 1)
        self.assertEqual(model["rows"][0]["deployment"]["state"], "Deployed")
        self.assertEqual(model["rows"][0]["name"], "Repository rule")
        self.assertEqual(model["rows"][0]["uuid"], "elastic-uuid-1")

    def test_repository_and_elastic_only_rules_are_separate(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(
                directory,
                [legacy_record(**{"Stable rule_id": "elastic-only"})],
            )
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)
            detection_directory = directory / "detections"
            write_detection(detection_directory, rule_id="repository-only")
            model = dashboard.dashboard_model(snapshot, dashboard.load_repository_rules(detection_directory))

        states = {row["deployment"]["state"] for row in model["rows"]}
        self.assertEqual(states, {"Repository-only", "Elastic-only"})

    def test_duplicate_names_are_candidates_but_distinguished_by_uuid(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(
                directory,
                [
                    legacy_record(**{"Elastic internal UUID": "uuid-a", "Rule name": "Same Name"}),
                    legacy_record(**{"Elastic internal UUID": "uuid-b", "Rule name": " same   name "}),
                ],
            )
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)
            model = dashboard.dashboard_model(snapshot, [])

        self.assertEqual(snapshot["duplicate_candidates"], [["uuid-a", "uuid-b"]])
        self.assertEqual([row["uuid"] for row in model["review_sections"]["duplicate_candidates"][0]], ["uuid-a", "uuid-b"])

    def test_duplicate_repository_stable_ids_are_not_unsafe_correlations(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(directory, [legacy_record()])
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)
            detection_directory = directory / "detections"
            first = write_detection(detection_directory, name="First duplicate")
            second = detection_directory / "second_duplicate.toml"
            second.write_text(first.read_text(encoding="utf-8").replace("First duplicate", "Second duplicate"), encoding="utf-8")
            model = dashboard.dashboard_model(snapshot, dashboard.load_repository_rules(detection_directory))

        self.assertEqual({row["deployment"]["state"] for row in model["rows"]}, {"Repository-only", "Elastic-only"})
        self.assertTrue(
            any("DUPLICATE_REPOSITORY_STABLE_ID" in row["review_flags"] for row in model["rows"])
        )
        self.assertTrue(
            any("AMBIGUOUS_REPOSITORY_STABLE_ID" in row["review_flags"] for row in model["rows"])
        )

    def test_html_escapes_untrusted_metadata_and_uses_text_content_rendering(self):
        snapshot = {
            "schema_version": 1,
            "generated_at": TIMESTAMP,
            "lookback": "now-30d",
            "collection": {"source_kind": "legacy_report_snapshot", "is_live": False},
            "inventory": [
                {
                    "name": "<script>alert(1)</script>",
                    "rule_id": "safe-id",
                    "uuid": "uuid-1",
                    "enabled": True,
                    "type": "query",
                    "interval": "5m",
                    "status": "HEALTHY",
                    "execution": {},
                    "alert_activity": None,
                    "alert_error": None,
                    "review_flags": ["ZERO_ALERTS_IN_LOOKBACK"],
                }
            ],
        }
        model = dashboard.dashboard_model(snapshot, [])
        html = dashboard.dashboard_html(model)

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", html)
        self.assertNotIn("innerHTML", dashboard.DASHBOARD_JS_CONTENT)
        self.assertIn("textContent", dashboard.DASHBOARD_JS_CONTENT)

    def test_generation_writes_static_assets_and_does_not_fabricate_effectiveness(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(
                directory,
                [legacy_record(**{"Alert count for selected lookback": "0", "Review flags": "ZERO_ALERTS_IN_LOOKBACK"})],
            )
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)
            detection_directory = directory / "detections"
            write_detection(detection_directory)
            model = dashboard.dashboard_model(snapshot, dashboard.load_repository_rules(detection_directory))
            targets = dashboard.generate_dashboard(model, directory)
            html = targets[dashboard.DASHBOARD_HTML].read_text(encoding="utf-8")

        self.assertTrue(targets[dashboard.DASHBOARD_CSS].name.endswith(".css"))
        self.assertIn('"is_live":false', html)
        self.assertIn('"Historical"', dashboard.DASHBOARD_JS_CONTENT)
        self.assertIn("Date.now()", dashboard.DASHBOARD_JS_CONTENT)
        self.assertEqual(model["rows"][0]["detection_effectiveness"]["status"], "Not assessed")
        self.assertNotIn("true_positive", json.dumps(model))
        self.assertNotIn("false_positive", json.dumps(model))

    def test_pages_site_contains_only_public_assets(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            csv_path, markdown_path = write_legacy_reports(directory, [legacy_record()])
            snapshot = dashboard.convert_legacy_reports(csv_path, markdown_path)
            model = dashboard.dashboard_model(snapshot, [])
            site_directory = directory / "site"
            targets = dashboard.generate_pages_site(model, site_directory)
            dashboard.validate_pages_site(site_directory)

        self.assertEqual(set(targets), {dashboard.PAGES_INDEX, dashboard.DASHBOARD_CSS, dashboard.DASHBOARD_JS})
        self.assertEqual(targets[dashboard.PAGES_INDEX].name, "index.html")

    def test_pages_site_rejects_snapshot_or_sensitive_configuration(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            directory.mkdir(exist_ok=True)
            for name in dashboard.PUBLISHED_SITE_FILENAMES:
                (directory / name).write_text("safe", encoding="utf-8")
            (directory / dashboard.SNAPSHOT_FILENAME).write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(dashboard.DashboardError, "unexpected"):
                dashboard.validate_pages_site(directory)
            (directory / dashboard.SNAPSHOT_FILENAME).unlink()
            (directory / dashboard.PAGES_INDEX).write_text("https://example.elastic.cloud", encoding="utf-8")
            with self.assertRaisesRegex(dashboard.DashboardError, "forbidden configuration marker"):
                dashboard.validate_pages_site(directory)

    def test_malformed_snapshot_fails_safely(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "bad.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(dashboard.DashboardError, "root must be a JSON object"):
                dashboard.load_snapshot(path)


if __name__ == "__main__":
    unittest.main()
