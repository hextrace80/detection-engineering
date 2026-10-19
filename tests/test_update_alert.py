"""Mocked unit tests for the Elastic detection deployment adapter."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "update_alert.py"
SPEC = importlib.util.spec_from_file_location("update_alert", SCRIPT_PATH)
update_alert = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(update_alert)

RULE_ID = "11111111-1111-4111-8111-111111111111"


class FakeResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def get(self, url, **kwargs):
        return self._request("get", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("post", url, **kwargs)

    def put(self, url, **kwargs):
        return self._request("put", url, **kwargs)


def query_rule(query="event.action: CreateAccessKey"):
    return {
        "author": ["Test Author"],
        "description": "Test query rule",
        "from": "now-10m",
        "index": ["logs-test-*"],
        "name": "Test rule",
        "query": query,
        "risk_score": 47,
        "rule_id": RULE_ID,
        "severity": "medium",
        "threat": [],
        "type": "query",
    }


def create_rule_file(repository_root, rule):
    detection_directory = repository_root / "detections"
    detection_directory.mkdir()
    lines = [
        "[rule]",
        "author = [\"Test Author\"]",
        "name = \"Test rule\"",
        "description = \"Test query rule\"",
        "risk_score = 47",
        "severity = \"medium\"",
        f"type = \"{rule['type']}\"",
        "from = \"now-10m\"",
        "index = [\"logs-test-*\"]",
        f"rule_id = \"{rule['rule_id']}\"",
        "threat = []",
    ]
    if "query" in rule:
        lines.append(f"query = \"{rule['query']}\"")

    (detection_directory / "test_rule.toml").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


class UpdateAlertTests(unittest.TestCase):
    def deploy(self, responses, rule=None):
        rule = rule or query_rule()
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            create_rule_file(repository_root, rule)
            session = FakeSession(responses)
            results = update_alert.deploy_changed_rules(
                "detections/test_rule.toml",
                "test-api-key",
                session=session,
                repository_root=repository_root,
            )
        return results, session

    def test_creates_missing_rule_with_documented_defaults(self):
        expected = query_rule()
        expected.update({"enabled": True, "interval": "5m", "to": "now", "language": "kuery"})
        results, session = self.deploy(
            [FakeResponse(404), FakeResponse(200, expected), FakeResponse(200, expected)]
        )

        self.assertEqual(results[0][2], "created")
        self.assertIsNone(results[0][3])
        self.assertEqual([call[0] for call in session.calls], ["get", "post", "get"])
        self.assertEqual(session.calls[1][2]["json"], expected)

    def test_updates_existing_rule_and_preserves_operational_settings(self):
        existing = query_rule(query="event.action: DeleteAccessKey")
        existing.update(
            {
                "actions": [{"group": "default", "id": "connector-id", "params": {}}],
                "alert_suppression": {"group_by": ["user.name"]},
                "enabled": True,
                "exceptions_list": [],
                "interval": "10m",
                "to": "now",
            }
        )
        expected = query_rule()
        expected.update(
            {
                "actions": existing["actions"],
                "alert_suppression": existing["alert_suppression"],
                "enabled": True,
                "exceptions_list": [],
                "interval": "10m",
                "language": "kuery",
                "to": "now",
            }
        )
        results, session = self.deploy(
            [FakeResponse(200, existing), FakeResponse(200, expected), FakeResponse(200, expected)]
        )

        self.assertEqual(results[0][2], "updated")
        self.assertIsNone(results[0][3])
        self.assertEqual([call[0] for call in session.calls], ["get", "put", "get"])
        self.assertEqual(session.calls[1][2]["json"], expected)

    def test_preserves_disabled_existing_rule(self):
        existing = query_rule(query="event.action: DeleteAccessKey")
        existing.update({"enabled": False, "interval": "5m", "to": "now"})
        expected = query_rule()
        expected.update({"enabled": False, "interval": "5m", "language": "kuery", "to": "now"})
        results, session = self.deploy(
            [FakeResponse(200, existing), FakeResponse(200, expected), FakeResponse(200, expected)]
        )

        self.assertIsNone(results[0][3])
        self.assertFalse(session.calls[1][2]["json"]["enabled"])

    def test_reports_api_failure_without_attempting_create_or_update(self):
        results, session = self.deploy([FakeResponse(500, text="server error")])

        self.assertEqual(results[0][2], "failed")
        self.assertIn("HTTP 500", results[0][3])
        self.assertEqual([call[0] for call in session.calls], ["get"])

    def test_reports_post_deployment_verification_mismatch(self):
        expected = query_rule()
        expected.update({"enabled": True, "interval": "5m", "to": "now", "language": "kuery"})
        mismatched = dict(expected)
        mismatched["query"] = "event.action: DeleteAccessKey"
        results, session = self.deploy(
            [FakeResponse(404), FakeResponse(200, expected), FakeResponse(200, mismatched)]
        )

        self.assertEqual(results[0][2], "failed")
        self.assertIn("Post-deployment verification failed", results[0][3])
        self.assertEqual([call[0] for call in session.calls], ["get", "post", "get"])

    def test_missing_required_toml_field_fails_before_any_http_request(self):
        incomplete_rule = query_rule()
        del incomplete_rule["query"]
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            create_rule_file(repository_root, incomplete_rule)
            session = FakeSession([])
            results = update_alert.deploy_changed_rules(
                "detections/test_rule.toml",
                "test-api-key",
                session=session,
                repository_root=repository_root,
            )

        self.assertEqual(results[0][2], "failed")
        self.assertIn("missing required fields", results[0][3])
        self.assertEqual(session.calls, [])

    def test_unsupported_rule_type_fails_explicitly_before_any_http_request(self):
        unsupported_rule = query_rule()
        unsupported_rule["type"] = "machine_learning"
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            create_rule_file(repository_root, unsupported_rule)
            session = FakeSession([])
            results = update_alert.deploy_changed_rules(
                "detections/test_rule.toml",
                "test-api-key",
                session=session,
                repository_root=repository_root,
            )

        self.assertEqual(results[0][2], "failed")
        self.assertIn("unsupported rule type", results[0][3])
        self.assertEqual(session.calls, [])

    def test_multiple_changed_rules_report_failure_when_one_deployment_fails(self):
        expected = query_rule()
        expected.update({"enabled": True, "interval": "5m", "to": "now", "language": "kuery"})
        second_rule_id = "22222222-2222-4222-8222-222222222222"
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            create_rule_file(repository_root, query_rule())
            second_rule = query_rule()
            second_rule["rule_id"] = second_rule_id
            (repository_root / "detections" / "second_rule.toml").write_text(
                (repository_root / "detections" / "test_rule.toml").read_text(encoding="utf-8").replace(
                    RULE_ID, second_rule_id
                ),
                encoding="utf-8",
            )
            session = FakeSession(
                [
                    FakeResponse(404),
                    FakeResponse(200, expected),
                    FakeResponse(200, expected),
                    FakeResponse(500, text="server error"),
                ]
            )
            results = update_alert.deploy_changed_rules(
                "detections/test_rule.toml detections/second_rule.toml",
                "test-api-key",
                session=session,
                repository_root=repository_root,
            )

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][2], "created")
        self.assertIsNone(results[0][3])
        self.assertEqual(results[1][2], "failed")
        self.assertIn("HTTP 500", results[1][3])
        self.assertTrue(any(error is not None for _, _, _, error in results))


if __name__ == "__main__":
    unittest.main()
