"""Mocked tests for the bounded, read-only detection-health investigation agent."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "health_agent.py"
SPEC = importlib.util.spec_from_file_location("health_agent", SCRIPT_PATH)
health_agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health_agent)


RULE_UUID = "11111111-1111-1111-1111-111111111111"


def snapshot(telemetry=None):
    row = {
        "uuid": RULE_UUID,
        "rule_id": "stable-rule-id",
        "name": "Example <untrusted> rule",
        "enabled": True,
        "type": "query",
        "interval": "5m",
        "status": "HEALTHY",
        "execution": {"status": "succeeded", "date": "2026-11-08T10:00:00Z"},
        "alert_activity": None,
        "alert_error": None,
        "review_flags": ["ZERO_ALERTS_IN_LOOKBACK"],
    }
    if telemetry is not None:
        row["telemetry"] = telemetry
    return {"schema_version": 1, "lookback": "now-30d", "inventory": [row]}


def call(name, call_id, rule_id=RULE_UUID):
    return {"type": "function_call", "name": name, "call_id": call_id, "arguments": json.dumps({"rule_id": rule_id})}


class FakeResponse:
    def __init__(self, output=None, output_text="", response_id="response-id"):
        self.output = output or []
        self.output_text = output_text
        self.id = response_id


class FakeResponses:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeClient:
    def __init__(self, responses):
        self.responses = FakeResponses(responses)


class FakeAPIStatusError(health_agent.APIStatusError):
    def __init__(self, status_code, body):
        Exception.__init__(self, "sensitive response body must not be exposed")
        self.status_code = status_code
        self.body = body


class FakeAPIConnectionError(health_agent.APIConnectionError):
    def __init__(self):
        Exception.__init__(self, "sensitive endpoint must not be exposed")


def final_json(action="Review the source with an analyst."):
    return json.dumps({
        "potential_causes": ["Telemetry may be intermittent."],
        "uncertainties": ["No controlled validation event was observed."],
        "recommended_action": action,
    })


class HealthAgentTests(unittest.TestCase):
    def write_fixture_files(self, directory, document=None):
        directory = Path(directory)
        snapshot_path = directory / "snapshot.json"
        snapshot_path.write_text(json.dumps(document or snapshot()), encoding="utf-8")
        detections = directory / "detections"
        detections.mkdir()
        (detections / "example.toml").write_text(
            "[rule]\nname = 'Example rule'\nrule_id = 'stable-rule-id'\ntype = 'query'\nindex = ['logs-example-*']\nquery = 'secret command text'\nseverity = 'medium'\nrisk_score = 47\n"
            "[[rule.threat.technique]]\nid = 'T1053'\nname = 'Scheduled Task/Job'\n",
            encoding="utf-8",
        )
        return snapshot_path, detections

    def test_selects_first_flagged_rule_or_exact_uuid(self):
        document = snapshot()
        selected = health_agent.select_rule(document)
        self.assertEqual(selected["uuid"], RULE_UUID)
        self.assertEqual(health_agent.select_rule(document, RULE_UUID)["name"], "Example <untrusted> rule")
        with self.assertRaisesRegex(health_agent.HealthAgentError, "not found"):
            health_agent.select_rule(document, "missing")

    def test_tools_return_bounded_evidence_and_preserve_not_assessed(self):
        document = snapshot()
        selected = health_agent.select_rule(document)
        with tempfile.TemporaryDirectory() as temporary:
            _, detections = self.write_fixture_files(temporary, document)
            tools = health_agent.EvidenceTools(document, selected, detections)
            details = tools.get_rule_details(RULE_UUID)
            health = tools.get_health_evidence(RULE_UUID)
            telemetry = tools.get_telemetry_evidence(RULE_UUID)
        self.assertTrue(details["query_available"])
        self.assertNotIn("query", details)
        self.assertEqual(health["alert_count"], None)
        self.assertEqual(telemetry["status"], "NOT_ASSESSED")

    def test_runs_tool_loop_and_forces_deterministic_human_review_output(self):
        client = FakeClient([
            FakeResponse([call("get_health_evidence", "call-1")]),
            FakeResponse(output_text=final_json()),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary)
            output = Path(temporary) / "findings.json"
            report = health_agent.run_investigation(snapshot_path, output, client=client, detections_directory=detections)
            stored = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report, stored)
        self.assertEqual(report["rule_id"], RULE_UUID)
        self.assertEqual(report["rule_name"], "Example <untrusted> rule")
        self.assertEqual(report["original_flags"], ["ZERO_ALERTS_IN_LOOKBACK"])
        self.assertTrue(report["requires_human_review"])
        self.assertEqual(report["evidence"][0]["tool"], "get_health_evidence")
        self.assertNotIn("secret command text", json.dumps(client.responses.calls[0]))
        self.assertEqual(client.responses.calls[0]["max_output_tokens"], health_agent.MAX_MODEL_OUTPUT_TOKENS)

    def test_rejects_unknown_invalid_and_repeated_tool_calls_without_writing_output(self):
        cases = [
            [FakeResponse([call("unknown_tool", "call-1")])],
            [FakeResponse([call("get_health_evidence", "call-1", "wrong-rule")])],
            [FakeResponse([call("get_health_evidence", "call-1")]), FakeResponse([call("get_health_evidence", "call-2")])],
        ]
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary)
            output = Path(temporary) / "findings.json"
            output.write_text("previous complete finding", encoding="utf-8")
            for responses in cases:
                with self.subTest(responses=responses):
                    with self.assertRaises(health_agent.HealthAgentError):
                        health_agent.run_investigation(snapshot_path, output, client=FakeClient(responses), detections_directory=detections)
                    self.assertEqual(output.read_text(encoding="utf-8"), "previous complete finding")

    def test_enforces_three_tool_call_limit(self):
        client = FakeClient([FakeResponse([
            call("get_health_evidence", "call-1"), call("get_telemetry_evidence", "call-2"),
            call("get_rule_details", "call-3"), call("get_health_evidence", "call-4"),
        ])])
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary)
            with self.assertRaisesRegex(health_agent.HealthAgentError, "tool-call limit"):
                health_agent.run_investigation(snapshot_path, Path(temporary) / "findings.json", client=client, detections_directory=detections)

    def test_preserves_unavailable_telemetry_and_rejects_malformed_model_output_or_api_errors(self):
        document = snapshot({"status": "UNAVAILABLE", "patterns": [{"index_pattern": "logs-x-*", "status": "UNAVAILABLE"}]})
        failures = [
            [FakeResponse([call("get_telemetry_evidence", "call-1")]), FakeResponse(output_text="not-json")],
            [RuntimeError("api key should not appear")],
        ]
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary, document)
            for responses in failures:
                with self.subTest(responses=responses):
                    with self.assertRaises(health_agent.HealthAgentError) as context:
                        health_agent.run_investigation(snapshot_path, Path(temporary) / "findings.json", client=FakeClient(responses), detections_directory=detections)
                    self.assertNotIn("api key", str(context.exception))
            tools = health_agent.EvidenceTools(document, health_agent.select_rule(document), detections)
            self.assertEqual(tools.get_telemetry_evidence(RULE_UUID)["status"], "UNAVAILABLE")

    def test_reports_safe_openai_http_error_categories(self):
        cases = (
            (400, {"type": "invalid_request_error", "code": "invalid_value", "message": "secret"}, "HTTP 400: invalid_request_error/invalid_value"),
            (401, {"error": {"type": "authentication_error", "code": "invalid_api_key", "message": "secret"}}, "HTTP 401: authentication_error/invalid_api_key"),
            (403, {"type": "permission_error", "code": "insufficient_quota", "message": "secret"}, "HTTP 403: permission_error/insufficient_quota"),
            (429, {"type": "rate_limit_error", "code": "rate_limit_exceeded", "message": "secret"}, "HTTP 429: rate_limit_error/rate_limit_exceeded"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary)
            for status, body, expected in cases:
                with self.subTest(status=status):
                    with self.assertRaisesRegex(health_agent.HealthAgentError, expected) as context:
                        health_agent.run_investigation(snapshot_path, Path(temporary) / "findings.json", client=FakeClient([FakeAPIStatusError(status, body)]), detections_directory=detections)
                    self.assertNotIn("secret", str(context.exception))

    def test_reports_openai_connection_failure_without_details(self):
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary)
            with self.assertRaisesRegex(health_agent.HealthAgentError, "connection failed") as context:
                health_agent.run_investigation(snapshot_path, Path(temporary) / "findings.json", client=FakeClient([FakeAPIConnectionError()]), detections_directory=detections)
        self.assertNotIn("endpoint", str(context.exception))

    def test_strict_report_validation_and_no_overwrite_on_failure(self):
        client = FakeClient([FakeResponse([call("get_rule_details", "call-1")]), FakeResponse(output_text=json.dumps({"potential_causes": [], "uncertainties": []}))])
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary)
            output = Path(temporary) / "findings.json"
            output.write_text("previous", encoding="utf-8")
            with self.assertRaisesRegex(health_agent.HealthAgentError, "invalid schema"):
                health_agent.run_investigation(snapshot_path, output, client=client, detections_directory=detections)
            self.assertEqual(output.read_text(encoding="utf-8"), "previous")

    def test_manual_workflow_is_isolated_and_uses_only_expected_secrets(self):
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "health_agent.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertIn("secrets.OPENAI_API_KEY", workflow)
        self.assertIn("secrets.ELASTIC_HEALTH_KEY", workflow)
        self.assertIn("python development/detection_health.py", workflow)
        self.assertIn("python development/health_agent.py", workflow)
        self.assertIn("actions/upload-artifact", workflow)
        self.assertNotIn("deploy-pages", workflow)
        self.assertNotIn("update_alert.py", workflow)


if __name__ == "__main__":
    unittest.main()
