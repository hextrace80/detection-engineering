"""Mocked tests for create-only publication of complete correlated auditd events."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "auditd_elastic_publisher.py"
CORRELATOR_PATH = REPOSITORY_ROOT / "development" / "auditd_correlator.py"
FIXTURE_PATH = REPOSITORY_ROOT / "tests" / "fixtures" / "auditd" / "execve_sequence_398.json"
SPEC = importlib.util.spec_from_file_location("auditd_elastic_publisher", SCRIPT_PATH)
auditd_elastic_publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auditd_elastic_publisher)
CORRELATOR_SPEC = importlib.util.spec_from_file_location("auditd_correlator_for_publisher_tests", CORRELATOR_PATH)
auditd_correlator = importlib.util.module_from_spec(CORRELATOR_SPEC)
CORRELATOR_SPEC.loader.exec_module(auditd_correlator)


def correlated_event():
    response = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return auditd_correlator.correlate_search_response(response)["correlated_events"][0]


def compatible_mapping_response():
    return {auditd_elastic_publisher.INDEX_NAME: auditd_elastic_publisher.index_definition()}


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, context):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body, "context": context})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class AuditdElasticPublisherTests(unittest.TestCase):
    def publish(self, events, transport, **overrides):
        configuration = {
            "endpoint": "https://example.es.elastic.cloud",
            "api_key": "test-publish-key",
            "publish": True,
            "transport": transport,
        }
        configuration.update(overrides)
        return auditd_elastic_publisher.publish_events(events, **configuration)

    def test_document_id_is_stable_and_uses_the_complete_correlation_key(self):
        event = correlated_event()
        same_key = copy.deepcopy(event)
        changed_key = copy.deepcopy(event)
        changed_key["correlation_key"]["host_id"] = "another-host"

        self.assertEqual(
            auditd_elastic_publisher.document_id(event),
            auditd_elastic_publisher.document_id(same_key),
        )
        self.assertNotEqual(
            auditd_elastic_publisher.document_id(event),
            auditd_elastic_publisher.document_id(changed_key),
        )

    def test_dry_run_is_default_and_never_uses_the_transport(self):
        transport = FakeTransport([])

        outcomes = auditd_elastic_publisher.publish_events([correlated_event()], transport=transport)

        self.assertEqual(outcomes[0]["status"], "dry-run")
        self.assertEqual(transport.calls, [])

    def test_successful_create_preserves_the_complete_event_body(self):
        event = correlated_event()
        transport = FakeTransport([compatible_mapping_response(), {"result": "created"}])

        outcomes = self.publish([event], transport)

        self.assertEqual(outcomes[0]["status"], "created")
        self.assertEqual(transport.calls[0]["method"], "GET")
        self.assertTrue(transport.calls[0]["url"].endswith("/auditd-correlated-events/_mapping"))
        self.assertEqual(transport.calls[1]["method"], "PUT")
        self.assertIn("/auditd-correlated-events/_create/", transport.calls[1]["url"])
        self.assertEqual(transport.calls[1]["body"], event)
        self.assertEqual(transport.calls[1]["body"]["source_records"], event["source_records"])
        self.assertEqual(transport.calls[1]["body"]["merged"], event["merged"])
        self.assertEqual(transport.calls[1]["body"]["conflicts"], event["conflicts"])

    def test_identical_rerun_is_reported_unchanged_after_create_conflict(self):
        event = correlated_event()
        transport = FakeTransport(
            [
                compatible_mapping_response(),
                auditd_elastic_publisher.ElasticsearchHttpError("create correlated event", 409, "conflict"),
                {"_source": copy.deepcopy(event)},
            ]
        )

        outcomes = self.publish([event], transport)

        self.assertEqual(outcomes[0]["status"], "unchanged")
        self.assertEqual(transport.calls[2]["method"], "GET")
        self.assertIn("/auditd-correlated-events/_doc/", transport.calls[2]["url"])

    def test_changed_document_with_same_key_is_conflict_and_is_not_overwritten(self):
        event = correlated_event()
        stored_event = copy.deepcopy(event)
        stored_event["source_records"] = []
        transport = FakeTransport(
            [
                compatible_mapping_response(),
                auditd_elastic_publisher.ElasticsearchHttpError("create correlated event", 409, "conflict"),
                {"_source": stored_event},
            ]
        )

        outcomes = self.publish([event], transport)

        self.assertEqual(outcomes[0]["status"], "conflict")
        self.assertIn("not overwritten", outcomes[0]["message"])
        self.assertEqual(len(transport.calls), 3)
        self.assertFalse(any(call["method"] in {"POST", "PATCH"} for call in transport.calls))

    def test_missing_index_fails_before_any_create_request(self):
        transport = FakeTransport(
            [auditd_elastic_publisher.ElasticsearchHttpError("verify target index mapping", 404, "not found")]
        )

        with self.assertRaisesRegex(auditd_elastic_publisher.PublisherError, "Create it separately"):
            self.publish([correlated_event()], transport)

        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0]["method"], "GET")

    def test_incompatible_mapping_fails_before_any_create_request(self):
        mapping = compatible_mapping_response()
        mapping[auditd_elastic_publisher.INDEX_NAME]["mappings"]["properties"]["source_records"]["enabled"] = True
        transport = FakeTransport([mapping])

        with self.assertRaisesRegex(auditd_elastic_publisher.PublisherError, "approved compatible mapping"):
            self.publish([correlated_event()], transport)

        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0]["method"], "GET")

    def test_elasticsearch_string_false_dynamic_mapping_is_compatible(self):
        actual_elasticsearch_mapping = compatible_mapping_response()
        actual_elasticsearch_mapping[auditd_elastic_publisher.INDEX_NAME]["mappings"]["dynamic"] = "false"

        self.assertTrue(auditd_elastic_publisher.mapping_is_compatible(actual_elasticsearch_mapping))

    def test_invalid_event_fails_before_any_http_request(self):
        event = correlated_event()
        del event["merged"]
        transport = FakeTransport([])

        with self.assertRaisesRegex(auditd_elastic_publisher.PublisherError, "merged"):
            self.publish([event], transport)

        self.assertEqual(transport.calls, [])

    def test_partial_batch_reports_failure_and_continues_with_other_events(self):
        first_event = correlated_event()
        second_event = copy.deepcopy(first_event)
        second_event["correlation_key"]["auditd_log_sequence"] = 399
        transport = FakeTransport(
            [
                compatible_mapping_response(),
                auditd_elastic_publisher.ElasticsearchHttpError("create correlated event", 503, "unavailable"),
                {"result": "created"},
            ]
        )

        outcomes = self.publish([first_event, second_event], transport)

        self.assertEqual([outcome["status"] for outcome in outcomes], ["failed", "created"])
        self.assertEqual(len(transport.calls), 3)
        self.assertIn("HTTP 503", outcomes[0]["message"])


if __name__ == "__main__":
    unittest.main()
