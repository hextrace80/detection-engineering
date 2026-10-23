"""Safely publish complete locally correlated auditd events to Elasticsearch."""

import argparse
import hashlib
import json
import os
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


INDEX_NAME = "auditd-correlated-events"
REQUIRED_EVENT_FIELDS = (
    "correlation_key",
    "record_types",
    "original_document_ids",
    "source_records",
    "merged",
    "missing_record_types",
    "conflicts",
    "duplicate_document_ids",
)


class PublisherError(RuntimeError):
    """Raised when a correlated-event publication cannot proceed safely."""


class ElasticsearchHttpError(PublisherError):
    """An Elasticsearch HTTP failure with safe operation metadata."""

    def __init__(self, operation, status, detail):
        self.operation = operation
        self.status = status
        super().__init__(f"Elasticsearch {operation} failed with HTTP {status}: {detail}")


def index_definition():
    """Return the manually applied mapping required before publish mode can run."""
    return {
        "mappings": {
            "dynamic": False,
            "properties": {
                "correlation_key": {
                    "properties": {
                        "host_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "auditd_log_sequence": {"type": "long"},
                    }
                },
                "record_types": {"type": "keyword"},
                "original_document_ids": {"type": "keyword"},
                "duplicate_document_ids": {"type": "keyword"},
                "missing_record_types": {"type": "keyword"},
                "source_records": {"type": "object", "enabled": False},
                "merged": {"type": "object", "enabled": False},
                "conflicts": {"type": "object", "enabled": False},
            },
        }
    }


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_event(event):
    if not isinstance(event, dict):
        raise PublisherError("Each correlated event must be an object")
    missing = [field for field in REQUIRED_EVENT_FIELDS if field not in event]
    if missing:
        raise PublisherError(f"Correlated event is missing required fields: {', '.join(missing)}")

    key = event["correlation_key"]
    if not isinstance(key, dict):
        raise PublisherError("correlation_key must be an object")
    host_id = key.get("host_id")
    timestamp = key.get("timestamp")
    sequence = key.get("auditd_log_sequence")
    if not isinstance(host_id, str) or not host_id:
        raise PublisherError("correlation_key.host_id must be a non-empty string")
    if not isinstance(timestamp, str) or not timestamp:
        raise PublisherError("correlation_key.timestamp must be a non-empty string")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise PublisherError("correlation_key.auditd_log_sequence must be an integer")

    expected_types = {
        "record_types": list,
        "original_document_ids": list,
        "source_records": list,
        "merged": dict,
        "missing_record_types": list,
        "conflicts": list,
        "duplicate_document_ids": list,
    }
    for field, expected_type in expected_types.items():
        if not isinstance(event[field], expected_type):
            raise PublisherError(f"{field} must be a {expected_type.__name__}")


def document_id(event):
    """Create a stable ID from the complete correlation key only."""
    validate_event(event)
    key = event["correlation_key"]
    identity = {
        "host_id": key["host_id"],
        "timestamp": key["timestamp"],
        "auditd_log_sequence": key["auditd_log_sequence"],
    }
    return hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


def validate_endpoint(endpoint):
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise PublisherError("ELASTIC_AUDITD_PUBLISH_URL must be a complete HTTPS URL")
    return endpoint.rstrip("/")


def api_headers(api_key):
    if not isinstance(api_key, str) or not api_key:
        raise PublisherError("ELASTIC_AUDITD_PUBLISH_API_KEY must be set")
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}",
    }


def ssl_context(certificate_path=None):
    try:
        return ssl.create_default_context(cafile=certificate_path)
    except (OSError, ssl.SSLError) as error:
        raise PublisherError(f"Could not load TLS certificate authority: {error}") from error


def safe_error_detail(body):
    try:
        payload = json.loads(body.decode("utf-8"))
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict):
            error_type = error.get("type")
            reason = error.get("reason")
            parts = []
            if isinstance(error_type, str):
                parts.append(f"type={error_type}")
            if isinstance(reason, str):
                parts.append(f"reason={' '.join(reason.split())[:500]}")
            if parts:
                return "; ".join(parts)
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return "Elasticsearch returned an unstructured error response"


def perform_request(operation, method, url, headers, body, context):
    request_headers = dict(headers)
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    if body is None:
        request_headers.pop("Content-Type", None)
    request = Request(url, data=data, headers=request_headers, method=method)
    try:
        with urlopen(request, context=context, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise ElasticsearchHttpError(operation, error.code, safe_error_detail(error.read())) from error
    except (URLError, OSError, TimeoutError, json.JSONDecodeError) as error:
        raise PublisherError(f"Elasticsearch {operation} request failed: {error}") from error


def request_json(operation, method, url, headers, body, context, transport=None):
    response = transport(method, url, headers, body, context) if transport else perform_request(operation, method, url, headers, body, context)
    if not isinstance(response, dict):
        raise PublisherError(f"Elasticsearch {operation} returned an unexpected JSON response")
    return response


def mapping_is_compatible(mapping_response):
    index_mapping = mapping_response.get(INDEX_NAME)
    mappings = index_mapping.get("mappings") if isinstance(index_mapping, dict) else None
    dynamic = mappings.get("dynamic") if isinstance(mappings, dict) else None
    if not isinstance(mappings, dict) or not (dynamic is False or (isinstance(dynamic, str) and dynamic == "false")):
        return False
    properties = mappings.get("properties")
    if not isinstance(properties, dict):
        return False

    expected_types = {
        "record_types": "keyword",
        "original_document_ids": "keyword",
        "duplicate_document_ids": "keyword",
        "missing_record_types": "keyword",
    }
    for field, field_type in expected_types.items():
        if properties.get(field, {}).get("type") != field_type:
            return False
    for field in ("source_records", "merged", "conflicts"):
        if properties.get(field, {}).get("enabled") is not False:
            return False

    key_properties = properties.get("correlation_key", {}).get("properties")
    return isinstance(key_properties, dict) and (
        key_properties.get("host_id", {}).get("type") == "keyword"
        and key_properties.get("timestamp", {}).get("type") == "date"
        and key_properties.get("auditd_log_sequence", {}).get("type") == "long"
    )


def require_compatible_index(endpoint, headers, context, transport=None):
    try:
        response = request_json(
            "verify target index mapping",
            "GET",
            f"{endpoint}/{INDEX_NAME}/_mapping",
            headers,
            None,
            context,
            transport,
        )
    except ElasticsearchHttpError as error:
        if error.status == 404:
            raise PublisherError(
                f"Target index {INDEX_NAME} is missing. Create it separately with the approved mapping before publishing."
            ) from error
        raise
    if not mapping_is_compatible(response):
        raise PublisherError(f"Target index {INDEX_NAME} is missing the approved compatible mapping; publishing was not attempted")


def existing_source(endpoint, document_identifier, headers, context, transport=None):
    response = request_json(
        "retrieve existing correlated event",
        "GET",
        f"{endpoint}/{INDEX_NAME}/_doc/{quote(document_identifier, safe='')}",
        headers,
        None,
        context,
        transport,
    )
    source = response.get("_source")
    if not isinstance(source, dict):
        raise PublisherError("Existing correlated event response is missing an object _source")
    return source


def publish_event(event, endpoint, headers, context, transport=None):
    identifier = document_id(event)
    try:
        response = request_json(
            "create correlated event",
            "PUT",
            f"{endpoint}/{INDEX_NAME}/_create/{quote(identifier, safe='')}",
            headers,
            event,
            context,
            transport,
        )
        if response.get("result") != "created":
            raise PublisherError("Create correlated event response did not confirm result=created")
        return {"document_id": identifier, "status": "created"}
    except ElasticsearchHttpError as error:
        if error.status != 409:
            return {"document_id": identifier, "status": "failed", "message": str(error)}
        try:
            stored_event = existing_source(endpoint, identifier, headers, context, transport)
        except PublisherError as comparison_error:
            return {"document_id": identifier, "status": "failed", "message": str(comparison_error)}
        if canonical_json(stored_event) == canonical_json(event):
            return {"document_id": identifier, "status": "unchanged"}
        return {
            "document_id": identifier,
            "status": "conflict",
            "message": "An existing correlated event has the same correlation key but different complete content; it was not overwritten.",
        }
    except PublisherError as error:
        return {"document_id": identifier, "status": "failed", "message": str(error)}


def publish_events(events, endpoint=None, api_key=None, publish=False, certificate_path=None, transport=None):
    if not isinstance(events, list):
        raise PublisherError("correlated_events must be a list")
    identifiers = [document_id(event) for event in events]
    if not publish:
        return [{"document_id": identifier, "status": "dry-run"} for identifier in identifiers]

    endpoint = validate_endpoint(endpoint)
    headers = api_headers(api_key)
    context = ssl_context(certificate_path)
    require_compatible_index(endpoint, headers, context, transport)
    return [publish_event(event, endpoint, headers, context, transport) for event in events]


def load_correlated_events(input_path):
    try:
        with Path(input_path).open(encoding="utf-8") as source_file:
            payload = json.load(source_file)
    except (OSError, json.JSONDecodeError) as error:
        raise PublisherError(f"Could not load correlated-event JSON {input_path}: {error}") from error
    if not isinstance(payload, dict):
        raise PublisherError("Correlated-event JSON root must be an object")
    events = payload.get("correlated_events")
    if not isinstance(events, list):
        raise PublisherError("Correlated-event JSON is missing a correlated_events list")
    return events


def configuration_from_environment():
    endpoint = os.environ.get("ELASTIC_AUDITD_PUBLISH_URL")
    api_key = os.environ.get("ELASTIC_AUDITD_PUBLISH_API_KEY")
    missing = [
        name
        for name, value in (("ELASTIC_AUDITD_PUBLISH_URL", endpoint), ("ELASTIC_AUDITD_PUBLISH_API_KEY", api_key))
        if not value
    ]
    if missing:
        raise PublisherError(f"Missing required environment variables: {', '.join(missing)}")
    return endpoint, api_key, os.environ.get("ELASTIC_AUDITD_PUBLISH_CA_CERT")


def print_outcomes(outcomes):
    for outcome in outcomes:
        message = f"{outcome['status'].upper():9} {outcome['document_id']}"
        if "message" in outcome:
            message = f"{message} — {outcome['message']}"
        print(message)
    counts = {}
    for outcome in outcomes:
        counts[outcome["status"]] = counts.get(outcome["status"], 0) + 1
    print("Summary: " + ", ".join(f"{status}={count}" for status, count in sorted(counts.items())))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Dry-run-first publisher for complete correlated auditd events.")
    parser.add_argument("--input", help="Path to JSON output from auditd_correlator.py")
    parser.add_argument("--publish", action="store_true", help="Perform create-only Elasticsearch writes; otherwise dry-run")
    parser.add_argument("--print-index-definition", action="store_true", help="Print the approved index-create JSON and exit")
    arguments = parser.parse_args(argv)

    if arguments.print_index_definition:
        print(json.dumps(index_definition(), indent=2))
        return 0
    if not arguments.input:
        parser.error("--input is required unless --print-index-definition is used")

    try:
        events = load_correlated_events(arguments.input)
        if arguments.publish:
            endpoint, api_key, certificate_path = configuration_from_environment()
            outcomes = publish_events(events, endpoint, api_key, True, certificate_path)
        else:
            outcomes = publish_events(events)
        print_outcomes(outcomes)
        return 1 if any(outcome["status"] in {"failed", "conflict"} for outcome in outcomes) else 0
    except PublisherError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
