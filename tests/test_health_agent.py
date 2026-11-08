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

    def test_replays_local_response_and_tool_history_with_store_disabled(self):
        first_call = call("get_health_evidence", "call-1")
        second_call = call("get_telemetry_evidence", "call-2")
        client = FakeClient([
            FakeResponse([first_call]),
            FakeResponse([second_call]),
            FakeResponse(output_text=final_json()),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary)
            health_agent.run_investigation(snapshot_path, Path(temporary) / "findings.json", client=client, detections_directory=detections)
        first, second, third = client.responses.calls
        self.assertTrue(all(call["store"] is False for call in (first, second, third)))
        self.assertTrue(all("previous_response_id" not in call for call in (first, second, third)))
        self.assertEqual(second["input"][1], first_call)
        self.assertEqual(second["input"][2]["type"], "function_call_output")
        self.assertEqual(second["input"][2]["call_id"], "call-1")
        self.assertEqual(third["input"][1], first_call)
        self.assertEqual(third["input"][3], second_call)
        self.assertEqual(third["input"][4]["call_id"], "call-2")
        self.assertEqual(second["instructions"], health_agent.SYSTEM_INSTRUCTIONS)

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
            self.assertEqual(tools.get_telemetry_evidence(RULE_UUID)["status"], "DEPENDENCY_UNVERIFIED")

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

    def test_batch_selection_modes_deduplicate_and_dry_run_without_openai(self):
        document = snapshot()
        healthy = dict(document["inventory"][0], uuid="22222222-2222-2222-2222-222222222222", review_flags=[])
        duplicate = dict(document["inventory"][0])
        document["inventory"].extend([healthy, duplicate])
        self.assertEqual([row["uuid"] for row in health_agent.select_rules(document, "flagged")], [RULE_UUID])
        self.assertEqual([row["uuid"] for row in health_agent.select_rules(document, "all")], [RULE_UUID, healthy["uuid"]])
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, _ = self.write_fixture_files(temporary, document)
            report = health_agent.run_batch(snapshot_path, Path(temporary) / "batch.json", mode="flagged", dry_run=True)
        self.assertTrue(report["dry_run"])
        self.assertEqual(report["selected_rule_uuids"], [RULE_UUID])
        with self.assertRaisesRegex(health_agent.HealthAgentError, "requires"):
            health_agent.select_rules(document, "single")

    def test_batch_survives_failure_resumes_successes_and_limits_requests(self):
        document = snapshot()
        second = dict(document["inventory"][0], uuid="22222222-2222-2222-2222-222222222222", rule_id="second-rule", name="Second", review_flags=["TELEMETRY_STALE"])
        document["inventory"].append(second)
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path, detections = self.write_fixture_files(temporary, document)
            (detections / "second.toml").write_text("[rule]\nrule_id='second-rule'\nname='Second'\nindex=['logs-example-*']\nquery='x'\n", encoding="utf-8")
            output = Path(temporary) / "batch.json"
            client = FakeClient([
                FakeResponse([call("get_health_evidence", "call-1")]), FakeResponse(output_text=final_json()),
                RuntimeError("failure"),
            ])
            report = health_agent.run_batch(snapshot_path, output, mode="flagged", client=client, detections_directory=detections)
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(len(report["errors"]), 1)
            resumed = health_agent.run_batch(snapshot_path, output, mode="flagged", resume=True, client=FakeClient([FakeResponse([call("get_health_evidence", "call-2", second["uuid"])]), FakeResponse(output_text=final_json())]), detections_directory=detections)
        self.assertEqual({item["rule_id"] for item in resumed["findings"]}, {RULE_UUID, second["uuid"]})

    def test_publication_requires_explicit_review_and_removes_private_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            batch = directory / "batch.json"
            batch.write_text(json.dumps({"findings": [{"rule_id": RULE_UUID, "rule_name": "Rule", "requires_human_review": True, "evidence": [{"secret": "private"}], "potential_causes": ["Cause"], "uncertainties": ["Unknown"], "recommended_action": "Review", "private_run_summary": {"completed_at": "2026-01-01T00:00:00Z"}}], "errors": []}), encoding="utf-8")
            approved = health_agent.prepare_publication(batch, RULE_UUID, "Human-reviewed summary", directory / "approved.json")
            stored = json.loads((directory / "approved.json").read_text(encoding="utf-8"))
        self.assertTrue(approved["reviewed"])
        self.assertNotIn("evidence", json.dumps(stored))
        self.assertEqual(stored["findings"][0]["rule_uuid"], RULE_UUID)

    def test_manifest_publication_supports_batch_approval_and_preserves_other_findings(self):
        second_uuid = "22222222-2222-2222-2222-222222222222"
        preserved_uuid = "33333333-3333-3333-3333-333333333333"
        finding = lambda rule_uuid, name: {
            "rule_id": rule_uuid, "rule_name": name, "requires_human_review": True,
            "evidence": [{"private": "never publish"}], "potential_causes": ["Cause"],
            "uncertainties": ["Unknown"], "recommended_action": "Review",
            "private_run_summary": {"completed_at": "2026-01-01T00:00:00Z"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            batch = directory / "batch.json"
            manifest = directory / "review.json"
            target = directory / "approved.json"
            batch.write_text(json.dumps({"findings": [finding(RULE_UUID, "First"), finding(second_uuid, "Second")], "errors": []}), encoding="utf-8")
            target.write_text(json.dumps({"schema_version": 1, "findings": [{"rule_uuid": preserved_uuid, "reviewed": True}]}), encoding="utf-8")
            manifest.write_text(json.dumps({"schema_version": 1, "approvals": [
                {"rule_uuid": RULE_UUID, "decision": "approved", "reviewed_summary": "Approved by analyst"},
                {"rule_uuid": second_uuid, "decision": "rejected", "reviewed_summary": "Not ready for publication"},
            ]}), encoding="utf-8")
            result = health_agent.prepare_publication_from_manifest(batch, manifest, target)
            stored = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual([item["rule_uuid"] for item in result["published"]], [RULE_UUID])
        self.assertEqual(result["rejected_rule_uuids"], [second_uuid])
        self.assertEqual({item["rule_uuid"] for item in stored["findings"]}, {RULE_UUID, preserved_uuid})
        self.assertNotIn("private", json.dumps(stored))

    def test_manifest_publication_rejects_invalid_duplicate_and_missing_approvals(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            batch = directory / "batch.json"
            manifest = directory / "review.json"
            batch.write_text(json.dumps({"findings": [], "errors": []}), encoding="utf-8")
            cases = (
                ({"schema_version": 1, "approvals": [{"rule_uuid": "not-a-uuid", "decision": "approved", "reviewed_summary": "Review"}]}, "must be a UUID"),
                ({"schema_version": 1, "approvals": [
                    {"rule_uuid": RULE_UUID, "decision": "approved", "reviewed_summary": "Review"},
                    {"rule_uuid": RULE_UUID, "decision": "rejected", "reviewed_summary": "Review"},
                ]}, "duplicate"),
                ({"schema_version": 1, "approvals": [{"rule_uuid": RULE_UUID, "decision": "approved", "reviewed_summary": "Review"}]}, "does not exist"),
            )
            for document, message in cases:
                with self.subTest(message=message):
                    manifest.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaisesRegex(health_agent.HealthAgentError, message):
                        health_agent.prepare_publication_from_manifest(batch, manifest, directory / "approved.json")

    def test_manifest_publication_rejects_private_or_duplicate_batch_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = directory / "review.json"
            batch = directory / "batch.json"
            manifest.write_text(json.dumps({"schema_version": 1, "approvals": [
                {"rule_uuid": RULE_UUID, "decision": "approved", "reviewed_summary": "Reviewed"},
            ]}), encoding="utf-8")
            batch.write_text(json.dumps({"findings": [
                {"rule_id": RULE_UUID, "requires_human_review": True},
                {"rule_id": RULE_UUID, "requires_human_review": True},
            ], "errors": []}), encoding="utf-8")
            with self.assertRaisesRegex(health_agent.HealthAgentError, "duplicate"):
                health_agent.prepare_publication_from_manifest(batch, manifest, directory / "approved.json")
            batch.write_text(json.dumps({"findings": [{"rule_id": "not-a-uuid"}], "errors": []}), encoding="utf-8")
            with self.assertRaisesRegex(health_agent.HealthAgentError, "must be a UUID"):
                health_agent.prepare_publication_from_manifest(batch, manifest, directory / "approved.json")


if __name__ == "__main__":
    unittest.main()
