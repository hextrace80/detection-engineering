"""Correlate locally saved auditd Elasticsearch search responses without network access."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


REQUIRED_RECORD_TYPES = ("SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE")


class CorrelationError(ValueError):
    """Raised when a saved search response cannot be correlated safely."""


def nested_value(document, *path):
    value = document
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def require_value(document, label, *path):
    value = nested_value(document, *path)
    if value is None or value == "":
        raise CorrelationError(f"Missing required {label}")
    return value


def record_details(hit):
    if not isinstance(hit, dict):
        raise CorrelationError("Search hit is not an object")
    document_id = hit.get("_id")
    if not isinstance(document_id, str) or not document_id:
        raise CorrelationError("Missing required Elasticsearch document _id")
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise CorrelationError(f"Document {document_id} is missing an object _source")

    host_id = require_value(source, "host.id", "host", "id")
    timestamp = require_value(source, "@timestamp", "@timestamp")
    sequence = require_value(source, "auditd.log.sequence", "auditd", "log", "sequence")
    record_type = require_value(source, "auditd.log.record_type", "auditd", "log", "record_type")
    if not isinstance(record_type, str):
        raise CorrelationError(f"Document {document_id} has a non-string auditd.log.record_type")

    return {
        "document_id": document_id,
        "source": source,
        "host_id": host_id,
        "timestamp": timestamp,
        "sequence": sequence,
        "record_type": record_type,
    }


def search_hits(search_response):
    hits = nested_value(search_response, "hits", "hits")
    if not isinstance(hits, list):
        raise CorrelationError("Search response is missing hits.hits")
    return hits


def stable_value_key(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def resolve_field(records, record_type, path, field_name, conflicts):
    values = defaultdict(list)
    for record in records:
        if record["record_type"] != record_type:
            continue
        value = nested_value(record["source"], *path)
        if value is not None:
            values[stable_value_key(value)].append({"document_id": record["document_id"], "value": value})

    if not values:
        return None
    if len(values) == 1:
        return next(iter(values.values()))[0]["value"]

    conflicts.append(
        {
            "field": field_name,
            "values": [
                {"value": entries[0]["value"], "document_ids": [entry["document_id"] for entry in entries]}
                for entries in values.values()
            ],
        }
    )
    return None


def path_item_sort_key(path_record):
    item = path_record["item"]
    try:
        return (0, int(item), path_record["source_position"])
    except (TypeError, ValueError):
        return (1, str(item), path_record["source_position"])


def correlate_group(group_key, records):
    record_counts = Counter(record["document_id"] for record in records)
    duplicate_document_ids = sorted(document_id for document_id, count in record_counts.items() if count > 1)
    unique_records = []
    seen_document_ids = set()
    for record in records:
        if record["document_id"] not in seen_document_ids:
            unique_records.append(record)
            seen_document_ids.add(record["document_id"])

    conflicts = []
    audit_log_path = ("auditd", "log")
    paths = []
    for source_position, record in enumerate(unique_records):
        if record["record_type"] != "PATH":
            continue
        metadata = nested_value(record["source"], *audit_log_path)
        paths.append(
            {
                "document_id": record["document_id"],
                "item": metadata.get("item") if isinstance(metadata, dict) else None,
                "metadata": metadata,
                "source_position": source_position,
            }
        )
    paths.sort(key=path_item_sort_key)
    for path in paths:
        path.pop("source_position")

    record_types = {record["record_type"] for record in unique_records}
    ordered_record_types = [record_type for record_type in REQUIRED_RECORD_TYPES if record_type in record_types]
    ordered_record_types.extend(sorted(record_types.difference(REQUIRED_RECORD_TYPES)))

    return {
        "correlation_key": {
            "host_id": group_key[0],
            "timestamp": group_key[1],
            "auditd_log_sequence": group_key[2],
        },
        "record_types": ordered_record_types,
        "original_document_ids": [record["document_id"] for record in records],
        "duplicate_document_ids": duplicate_document_ids,
        "source_records": [record["source_hit"] for record in records],
        "merged": {
            "process": {
                "syscall_executable": resolve_field(
                    unique_records, "SYSCALL", ("process", "executable"), "process.syscall_executable", conflicts
                ),
                "invocation_executable": resolve_field(
                    unique_records, "EXECVE", ("process", "executable"), "process.invocation_executable", conflicts
                ),
                "decoded_arguments": resolve_field(
                    unique_records,
                    "EXECVE",
                    ("auditd_normalization", "decoded_args"),
                    "process.decoded_arguments",
                    conflicts,
                ),
                "original_arguments": resolve_field(
                    unique_records,
                    "EXECVE",
                    ("auditd_normalization", "original_args"),
                    "process.original_arguments",
                    conflicts,
                ),
                "indexed_arguments": resolve_field(
                    unique_records, "EXECVE", ("process", "args"), "process.indexed_arguments", conflicts
                ),
                "pid": resolve_field(unique_records, "SYSCALL", ("process", "pid"), "process.pid", conflicts),
                "parent_pid": resolve_field(
                    unique_records, "SYSCALL", ("process", "parent", "pid"), "process.parent_pid", conflicts
                ),
            },
            "user": resolve_field(unique_records, "SYSCALL", ("user",), "user", conflicts),
            "working_directory": resolve_field(
                unique_records, "CWD", ("process", "working_directory"), "working_directory", conflicts
            ),
            "success": resolve_field(unique_records, "SYSCALL", ("auditd", "log", "success"), "success", conflicts),
            "proctitle": resolve_field(
                unique_records, "PROCTITLE", ("auditd", "log", "proctitle"), "proctitle", conflicts
            ),
            "paths": paths,
        },
        "missing_record_types": [record_type for record_type in REQUIRED_RECORD_TYPES if record_type not in record_types],
        "conflicts": conflicts,
    }


def correlate_search_response(search_response):
    groups = defaultdict(list)
    for hit in search_hits(search_response):
        record = record_details(hit)
        record["source_hit"] = hit
        group_key = (record["host_id"], record["timestamp"], record["sequence"])
        groups[group_key].append(record)

    correlated = [correlate_group(group_key, records) for group_key, records in groups.items()]
    return {"correlated_events": correlated}


def load_search_response(path):
    try:
        with Path(path).open(encoding="utf-8") as fixture_file:
            response = json.load(fixture_file)
    except (OSError, json.JSONDecodeError) as error:
        raise CorrelationError(f"Could not load search response {path}: {error}") from error
    if not isinstance(response, dict):
        raise CorrelationError("Search response root must be an object")
    return response


def write_json(output, output_path=None):
    if output_path is None:
        json.dump(output, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    try:
        with Path(output_path).open("w", encoding="utf-8", newline="") as destination:
            json.dump(output, destination, indent=2, ensure_ascii=False)
            destination.write("\n")
    except OSError as error:
        raise CorrelationError(f"Could not write output {output_path}: {error}") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description="Correlate a saved auditd Elasticsearch _search response locally.")
    parser.add_argument("input", help="Path to a saved Elasticsearch _search JSON response")
    parser.add_argument("--output", help="Optional local JSON output path; defaults to standard output")
    arguments = parser.parse_args(argv)
    try:
        write_json(correlate_search_response(load_search_response(arguments.input)), arguments.output)
    except CorrelationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
