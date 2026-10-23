"""Mocked tests for read-only auditd Elasticsearch retrieval."""

import copy
from email.message import Message
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "auditd_elastic_reader.py"
FIXTURE_PATH = REPOSITORY_ROOT / "tests" / "fixtures" / "auditd" / "execve_sequence_398.json"
SPEC = importlib.util.spec_from_file_location("auditd_elastic_reader", SCRIPT_PATH)
auditd_elastic_reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auditd_elastic_reader)


def search_page(hits, pit_id=None, timed_out=False, failed_shards=0):
    response = {
        "timed_out": timed_out,
        "_shards": {"failed": failed_shards},
        "hits": {"hits": hits},
    }
    if pit_id is not None:
        response["pit_id"] = pit_id
    return response


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


class AuditdElasticReaderTests(unittest.TestCase):
    def retrieve(self, transport, **overrides):
        configuration = {
            "endpoint": "https://example.es.elastic.cloud",
            "api_key": "test-key",
            "start": "2026-10-20T01:48:58Z",
            "end": "2026-10-20T01:49:01Z",
            "host_id": "5b049916a43446e7a7413d711f19a0bb",
            "sequence": 398,
            "page_size": 2,
            "max_documents": 10,
            "transport": transport,
        }
        configuration.update(overrides)
        return auditd_elastic_reader.retrieve_hits(**configuration)

    def test_api_key_header_is_constructed_without_logging_or_storage(self):
        headers = auditd_elastic_reader.api_headers("encoded-api-key")

        self.assertEqual(headers["Authorization"], "ApiKey encoded-api-key")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_http_400_reports_operation_and_structured_elasticsearch_error_without_credentials(self):
        error_body = json.dumps(
            {
                "error": {
                    "type": "illegal_argument_exception",
                    "reason": "point in time is not supported for this target",
                    "root_cause": [
                        {
                            "type": "illegal_argument_exception",
                            "reason": "point in time is not supported for this target",
                        }
                    ],
                }
            }
        ).encode("utf-8")
        response_headers = Message()
        response_headers["Content-Type"] = "text/html; charset=utf-8"
        http_error = HTTPError(
            "https://example.es.elastic.cloud/_pit",
            400,
            "Bad Request",
            response_headers,
            io.BytesIO(error_body),
        )
        with patch.object(auditd_elastic_reader, "urlopen", side_effect=http_error):
            with self.assertRaises(auditd_elastic_reader.ReaderError) as raised:
                auditd_elastic_reader.perform_request(
                    "open PIT",
                    "POST",
                    "https://example.es.elastic.cloud/logs-auditd.log-default/_pit?keep_alive=1m",
                    {"Authorization": "ApiKey test-secret"},
                    None,
                    object(),
                )

        message = str(raised.exception)
        self.assertIn("operation=open PIT", message)
        self.assertIn("method=POST", message)
        self.assertIn("path=/logs-auditd.log-default/_pit?keep_alive=1m", message)
        self.assertIn("status=400", message)
        self.assertIn("response_content_type=text/html", message)
        self.assertIn("type=illegal_argument_exception", message)
        self.assertIn("reason=point in time is not supported for this target", message)
        self.assertIn("root_causes=[", message)
        self.assertNotIn("test-secret", message)
        self.assertNotIn("Authorization", message)

    def test_open_pit_uses_bodyless_post_and_exact_path_without_content_type(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self):
                return b'{"id":"pit-one"}'

        def fake_urlopen(request, context, timeout):
            captured["request"] = request
            captured["context"] = context
            captured["timeout"] = timeout
            return FakeResponse()

        with patch.object(auditd_elastic_reader, "urlopen", side_effect=fake_urlopen):
            pit_id = auditd_elastic_reader.open_pit(
                "https://example.es.elastic.cloud/",
                auditd_elastic_reader.api_headers("test-key"),
                object(),
            )

        request = captured["request"]
        request_headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(pit_id, "pit-one")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            request.full_url,
            "https://example.es.elastic.cloud/logs-auditd.log-default/_pit?keep_alive=1m",
        )
        self.assertIsNone(request.data)
        self.assertNotIn("content-type", request_headers)
        self.assertEqual(request_headers["authorization"], "ApiKey test-key")

    def test_pagination_uses_latest_pit_id_and_returns_all_hits(self):
        first_hit = {"_id": "one", "sort": ["2026-10-20T01:48:59.544Z", 1]}
        second_hit = {"_id": "two", "sort": ["2026-10-20T01:48:59.545Z", 2]}
        transport = FakeTransport(
            [
                {"id": "pit-one"},
                search_page([first_hit, second_hit], pit_id="pit-two"),
                search_page([], pit_id="pit-three"),
                {"succeeded": True},
            ]
        )

        response = self.retrieve(transport)

        self.assertEqual(response["hits"]["hits"], [first_hit, second_hit])
        self.assertEqual(transport.calls[2]["body"]["pit"]["id"], "pit-two")
        self.assertEqual(transport.calls[2]["body"]["search_after"], second_hit["sort"])
        self.assertEqual(transport.calls[3]["body"], {"id": "pit-three"})

    def test_limit_exceedance_fails_without_returning_partial_hits(self):
        transport = FakeTransport(
            [
                {"id": "pit-one"},
                search_page([{"_id": "one"}, {"_id": "two"}]),
                {"succeeded": True},
            ]
        )

        with self.assertRaisesRegex(auditd_elastic_reader.ReaderError, "Maximum document count"):
            self.retrieve(transport, max_documents=1)
        self.assertEqual(transport.calls[-1]["method"], "DELETE")
        self.assertEqual(transport.calls[-1]["body"], {"id": "pit-one"})

    def test_timeout_failure_still_closes_latest_pit_id(self):
        transport = FakeTransport(
            [
                {"id": "pit-one"},
                search_page([], pit_id="pit-two", timed_out=True),
                {"succeeded": True},
            ]
        )

        with self.assertRaisesRegex(auditd_elastic_reader.ReaderError, "timed out"):
            self.retrieve(transport)
        self.assertEqual(transport.calls[-1]["method"], "DELETE")
        self.assertEqual(transport.calls[-1]["body"], {"id": "pit-two"})

    def test_invalid_search_response_is_rejected_and_pit_is_closed(self):
        transport = FakeTransport(
            [
                {"id": "pit-one"},
                {"timed_out": False, "_shards": {"failed": 0}, "hits": {}},
                {"succeeded": True},
            ]
        )

        with self.assertRaisesRegex(auditd_elastic_reader.ReaderError, "hits.hits"):
            self.retrieve(transport)
        self.assertEqual(transport.calls[-1]["method"], "DELETE")

    def test_connection_error_is_reported_and_pit_is_closed(self):
        transport = FakeTransport(
            [
                {"id": "pit-one"},
                auditd_elastic_reader.ReaderError("Elasticsearch request failed: connection refused"),
                {"succeeded": True},
            ]
        )

        with self.assertRaisesRegex(auditd_elastic_reader.ReaderError, "connection refused"):
            self.retrieve(transport)
        self.assertEqual(transport.calls[-1]["method"], "DELETE")

    def test_retrieved_fixture_handoffs_to_existing_correlator(self):
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        hits = copy.deepcopy(fixture["hits"]["hits"])
        transport = FakeTransport(
            [
                {"id": "pit-one"},
                search_page(hits, pit_id="pit-two"),
                {"succeeded": True},
            ]
        )

        response = self.retrieve(transport, page_size=10)
        correlated = auditd_elastic_reader.correlate_search_response(response)

        self.assertEqual(len(response["hits"]["hits"]), 6)
        self.assertEqual(len(correlated["correlated_events"]), 1)
        self.assertEqual(correlated["correlated_events"][0]["correlation_key"]["auditd_log_sequence"], 398)


if __name__ == "__main__":
    unittest.main()
