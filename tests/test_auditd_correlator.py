"""Tests for local auditd Elasticsearch search-response correlation."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "auditd_correlator.py"
FIXTURE_PATH = REPOSITORY_ROOT / "tests" / "fixtures" / "auditd" / "execve_sequence_398.json"
SPEC = importlib.util.spec_from_file_location("auditd_correlator", SCRIPT_PATH)
auditd_correlator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auditd_correlator)


def load_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


class AuditdCorrelatorTests(unittest.TestCase):
    def test_real_six_record_fixture_is_merged_without_losing_source_records(self):
        output = auditd_correlator.correlate_search_response(load_fixture())

        self.assertEqual(len(output["correlated_events"]), 1)
        event = output["correlated_events"][0]
        self.assertEqual(event["correlation_key"], {
            "host_id": "5b049916a43446e7a7413d711f19a0bb",
            "timestamp": "2026-10-20T01:48:59.544Z",
            "auditd_log_sequence": 398,
        })
        self.assertEqual(event["record_types"], ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"])
        self.assertEqual(len(event["source_records"]), 6)
        self.assertEqual(len(event["original_document_ids"]), 6)
        self.assertEqual(event["missing_record_types"], [])
        self.assertEqual(event["conflicts"], [])

        merged = event["merged"]
        self.assertEqual(merged["process"]["syscall_executable"], "/usr/lib/cargo/bin/coreutils/echo")
        self.assertEqual(merged["process"]["invocation_executable"], "/bin/echo")
        self.assertEqual(merged["process"]["decoded_arguments"], ["/bin/echo", "auditd normalization test"])
        self.assertEqual(
            merged["process"]["original_arguments"],
            ["/bin/echo", "617564697464206E6F726D616C697A6174696F6E2074657374"],
        )
        self.assertEqual(merged["process"]["pid"], 7141)
        self.assertEqual(merged["process"]["parent_pid"], 5493)
        self.assertEqual(merged["user"]["name"], "zeek")
        self.assertEqual(merged["working_directory"], "/home/zeek")
        self.assertTrue(merged["success"])
        self.assertEqual(merged["proctitle"], "/bin/echo^@auditd normalization test")
        self.assertEqual([path["item"] for path in merged["paths"]], ["0", "1"])
        self.assertEqual([path["metadata"]["name"] for path in merged["paths"]], ["/bin/echo", "/lib64/ld-linux-x86-64.so.2"])

    def test_shuffled_hits_keep_the_same_normalized_event_and_path_order(self):
        response = load_fixture()
        response["hits"]["hits"] = list(reversed(response["hits"]["hits"]))

        event = auditd_correlator.correlate_search_response(response)["correlated_events"][0]

        self.assertEqual(event["record_types"], ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"])
        self.assertEqual(event["merged"]["process"]["syscall_executable"], "/usr/lib/cargo/bin/coreutils/echo")
        self.assertEqual(event["merged"]["process"]["invocation_executable"], "/bin/echo")
        self.assertEqual([path["item"] for path in event["merged"]["paths"]], ["0", "1"])

    def test_duplicate_document_id_is_flagged_but_not_merged_as_an_extra_path(self):
        response = load_fixture()
        response["hits"]["hits"].append(copy.deepcopy(response["hits"]["hits"][3]))

        event = auditd_correlator.correlate_search_response(response)["correlated_events"][0]

        self.assertEqual(len(event["source_records"]), 7)
        self.assertEqual(event["duplicate_document_ids"], ["AaFW_0gKyge4__uNfbsd"])
        self.assertEqual(len(event["merged"]["paths"]), 2)

    def test_missing_record_type_is_reported_without_inventing_data(self):
        response = load_fixture()
        response["hits"]["hits"] = [
            hit for hit in response["hits"]["hits"] if hit["_source"]["auditd"]["log"]["record_type"] != "CWD"
        ]

        event = auditd_correlator.correlate_search_response(response)["correlated_events"][0]

        self.assertEqual(event["missing_record_types"], ["CWD"])
        self.assertIsNone(event["merged"]["working_directory"])

    def test_same_sequence_on_different_hosts_creates_separate_events(self):
        response = load_fixture()
        second_host_records = copy.deepcopy(response["hits"]["hits"])
        for hit in second_host_records:
            hit["_id"] = f"host-two-{hit['_id']}"
            hit["_source"]["host"]["id"] = "second-host-id"
        response["hits"]["hits"].extend(second_host_records)

        events = auditd_correlator.correlate_search_response(response)["correlated_events"]

        self.assertEqual(len(events), 2)
        self.assertEqual({event["correlation_key"]["host_id"] for event in events}, {"5b049916a43446e7a7413d711f19a0bb", "second-host-id"})

    def test_missing_grouping_key_is_rejected(self):
        response = load_fixture()
        del response["hits"]["hits"][0]["_source"]["host"]["id"]

        with self.assertRaisesRegex(auditd_correlator.CorrelationError, "host.id"):
            auditd_correlator.correlate_search_response(response)

    def test_conflicting_values_are_null_and_described(self):
        response = load_fixture()
        conflicting_syscall = copy.deepcopy(response["hits"]["hits"][0])
        conflicting_syscall["_id"] = "conflicting-syscall"
        conflicting_syscall["_source"]["process"]["executable"] = "/unexpected/executable"
        response["hits"]["hits"].append(conflicting_syscall)

        event = auditd_correlator.correlate_search_response(response)["correlated_events"][0]

        self.assertIsNone(event["merged"]["process"]["syscall_executable"])
        conflict = next(item for item in event["conflicts"] if item["field"] == "process.syscall_executable")
        self.assertEqual({entry["value"] for entry in conflict["values"]}, {"/usr/lib/cargo/bin/coreutils/echo", "/unexpected/executable"})

    def test_json_output_is_written_only_to_the_requested_local_path(self):
        output = auditd_correlator.correlate_search_response(load_fixture())
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "correlated.json"
            auditd_correlator.write_json(output, destination)
            saved = json.loads(destination.read_text(encoding="utf-8"))

        self.assertEqual(saved, output)


if __name__ == "__main__":
    unittest.main()
