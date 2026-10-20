"""Read-only retrieval of auditd records from Elasticsearch for local correlation."""

import argparse
import json
import os
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


MODULE_DIRECTORY = Path(__file__).resolve().parent
if str(MODULE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(MODULE_DIRECTORY))

from auditd_correlator import CorrelationError, correlate_search_response, write_json


DATA_STREAM = "logs-auditd.log-default"
DEFAULT_PAGE_SIZE = 500
DEFAULT_MAX_DOCUMENTS = 10_000
PIT_KEEP_ALIVE = "1m"


class ReaderError(RuntimeError):
    """Raised when Elasticsearch retrieval cannot complete safely."""


def api_headers(api_key):
    if not isinstance(api_key, str) or not api_key:
        raise ReaderError("ELASTIC_AUDITD_API_KEY must be set")
    return {"Accept": "application/json", "Content-Type": "application/json", "Authorization": f"ApiKey {api_key}"}


def validate_endpoint(endpoint):
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ReaderError("ELASTIC_AUDITD_URL must be a complete HTTPS URL")
    return endpoint.rstrip("/")


def ssl_context(certificate_path=None):
    try:
        return ssl.create_default_context(cafile=certificate_path)
    except (OSError, ssl.SSLError) as error:
        raise ReaderError(f"Could not load TLS certificate authority: {error}") from error


def response_json(response, context):
    if not isinstance(response, dict):
        raise ReaderError(f"{context}: Elasticsearch returned an unexpected JSON response")
    return response


def compact_text(value):
    return " ".join(value.split())[:500] if isinstance(value, str) else None


def elasticsearch_error_detail(body):
    try:
        document = json.loads(body.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        return "Elasticsearch returned a non-JSON error response"
    error = document.get("error") if isinstance(document, dict) else None
    if not isinstance(error, dict):
        return "Elasticsearch returned an error response without structured error details"

    details = []
    error_type = compact_text(error.get("type"))
    reason = compact_text(error.get("reason"))
    if error_type:
        details.append(f"type={error_type}")
    if reason:
        details.append(f"reason={reason}")

    root_causes = error.get("root_cause")
    if isinstance(root_causes, list):
        formatted_causes = []
        for root_cause in root_causes[:3]:
            if not isinstance(root_cause, dict):
                continue
            cause_type = compact_text(root_cause.get("type"))
            cause_reason = compact_text(root_cause.get("reason"))
            cause_parts = [part for part in (f"type={cause_type}" if cause_type else None, f"reason={cause_reason}" if cause_reason else None) if part]
            if cause_parts:
                formatted_causes.append(", ".join(cause_parts))
        if formatted_causes:
            details.append(f"root_causes=[{' | '.join(formatted_causes)}]")

    return "; ".join(details) if details else "Elasticsearch returned structured error details without type or reason"


def request_path(url):
    parsed = urlsplit(url)
    return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path


def response_content_type(headers):
    if headers is None:
        return "unknown"
    try:
        content_type = headers.get_content_type()
    except AttributeError:
        return "unknown"
    return compact_text(content_type) or "unknown"


def perform_request(operation, method, url, headers, body, context):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request_headers = dict(headers)
    if body is None:
        request_headers.pop("Content-Type", None)
    request = Request(url, data=data, headers=request_headers, method=method)
    try:
        with urlopen(request, context=context, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise ReaderError(
            "Elasticsearch request failed: "
            f"operation={operation}; method={method}; path={request_path(url)}; status={error.code}; "
            f"response_content_type={response_content_type(error.headers)}; details={elasticsearch_error_detail(error.read())}"
        ) from error
    except (URLError, OSError, TimeoutError, json.JSONDecodeError) as error:
        raise ReaderError(f"Elasticsearch request failed: {error}") from error


def request_json(operation, method, url, headers, body, context, transport=None):
    response = transport(method, url, headers, body, context) if transport else perform_request(operation, method, url, headers, body, context)
    return response_json(response, operation)


def open_pit(endpoint, headers, context, transport=None):
    endpoint = endpoint.rstrip("/")
    response = request_json(
        "open PIT",
        "POST",
        f"{endpoint}/{DATA_STREAM}/_pit?keep_alive={PIT_KEEP_ALIVE}",
        headers,
        None,
        context,
        transport,
    )
    pit_id = response.get("id")
    if not isinstance(pit_id, str) or not pit_id:
        raise ReaderError("Open PIT response did not include a usable id")
    return pit_id


def close_pit(endpoint, pit_id, headers, context, transport=None):
    endpoint = endpoint.rstrip("/")
    response = request_json("close PIT", "DELETE", f"{endpoint}/_pit", headers, {"id": pit_id}, context, transport)
    if response.get("succeeded") is not True:
        raise ReaderError("Close PIT response did not confirm successful cleanup")


def search_body(pit_id, start, end, host_id, sequence, page_size, search_after=None):
    filters = [{"range": {"@timestamp": {"gte": start, "lte": end}}}]
    if host_id is not None:
        filters.append({"term": {"host.id": host_id}})
    if sequence is not None:
        filters.append({"term": {"auditd.log.sequence": sequence}})

    body = {
        "size": page_size,
        "track_total_hits": False,
        "pit": {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE},
        "sort": [
            {"@timestamp": {"order": "asc", "format": "strict_date_optional_time_nanos"}},
            {"_shard_doc": "asc"},
        ],
        "query": {"bool": {"filter": filters}},
    }
    if search_after is not None:
        body["search_after"] = search_after
    return body


def validate_search_page(response):
    timed_out = response.get("timed_out")
    if not isinstance(timed_out, bool):
        raise ReaderError("Elasticsearch search response has an invalid timed_out value")
    if timed_out:
        raise ReaderError("Elasticsearch search timed out; retrieval is incomplete")
    shards = response.get("_shards")
    if not isinstance(shards, dict) or not isinstance(shards.get("failed"), int):
        raise ReaderError("Elasticsearch search response has invalid shard metadata")
    if shards["failed"] > 0:
        raise ReaderError("Elasticsearch search reported shard failures; retrieval is incomplete")
    hits = response.get("hits", {}).get("hits")
    if not isinstance(hits, list):
        raise ReaderError("Elasticsearch search response is missing hits.hits")
    return hits


def retrieve_hits(endpoint, api_key, start, end, host_id=None, sequence=None, page_size=DEFAULT_PAGE_SIZE, max_documents=DEFAULT_MAX_DOCUMENTS, certificate_path=None, transport=None):
    if not isinstance(start, str) or not start or not isinstance(end, str) or not end:
        raise ReaderError("Start and end timestamps are required")
    if page_size <= 0 or max_documents <= 0:
        raise ReaderError("Page size and maximum document count must be positive")

    endpoint = validate_endpoint(endpoint)
    headers = api_headers(api_key)
    context = ssl_context(certificate_path)
    pit_id = None
    retrieval_error = None
    collected_hits = []
    search_after = None
    try:
        pit_id = open_pit(endpoint, headers, context, transport)
        while True:
            response = request_json(
                "search auditd records",
                "POST",
                f"{endpoint}/_search?allow_partial_search_results=false",
                headers,
                search_body(pit_id, start, end, host_id, sequence, page_size, search_after),
                context,
                transport,
            )
            latest_pit_id = response.get("pit_id")
            if latest_pit_id is not None:
                if not isinstance(latest_pit_id, str) or not latest_pit_id:
                    raise ReaderError("Elasticsearch search returned an invalid PIT id")
                pit_id = latest_pit_id
            page_hits = validate_search_page(response)
            if len(collected_hits) + len(page_hits) > max_documents:
                raise ReaderError(f"Maximum document count of {max_documents} would be exceeded; narrow the query")
            collected_hits.extend(page_hits)
            if not page_hits or len(page_hits) < page_size:
                return {"hits": {"hits": collected_hits}}

            next_search_after = page_hits[-1].get("sort") if isinstance(page_hits[-1], dict) else None
            if not isinstance(next_search_after, list) or not next_search_after:
                raise ReaderError("Elasticsearch search hit is missing sort values required for pagination")
            search_after = next_search_after
    except ReaderError as error:
        retrieval_error = error
        raise
    finally:
        if pit_id is not None:
            try:
                close_pit(endpoint, pit_id, headers, context, transport)
            except ReaderError as cleanup_error:
                if retrieval_error is None:
                    raise ReaderError(f"PIT cleanup failed after retrieval: {cleanup_error}") from cleanup_error


def configuration_from_environment():
    endpoint = os.environ.get("ELASTIC_AUDITD_URL")
    api_key = os.environ.get("ELASTIC_AUDITD_API_KEY")
    missing = [name for name, value in (("ELASTIC_AUDITD_URL", endpoint), ("ELASTIC_AUDITD_API_KEY", api_key)) if not value]
    if missing:
        raise ReaderError(f"Missing required environment variables: {', '.join(missing)}")
    return endpoint, api_key, os.environ.get("ELASTIC_AUDITD_CA_CERT")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Retrieve and correlate auditd records from Elasticsearch over HTTPS.")
    parser.add_argument("--start", required=True, help="Inclusive ISO-8601 start timestamp")
    parser.add_argument("--end", required=True, help="Inclusive ISO-8601 end timestamp")
    parser.add_argument("--host-id", help="Optional exact host.id filter")
    parser.add_argument("--sequence", type=int, help="Optional exact auditd.log.sequence filter")
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, help=f"Hits per Elasticsearch page (default: {DEFAULT_PAGE_SIZE})")
    parser.add_argument("--max-documents", type=int, default=DEFAULT_MAX_DOCUMENTS, help=f"Fail above this many hits (default: {DEFAULT_MAX_DOCUMENTS})")
    parser.add_argument("--output", required=True, help="Local path for correlated JSON output")
    arguments = parser.parse_args(argv)
    try:
        endpoint, api_key, certificate_path = configuration_from_environment()
        search_response = retrieve_hits(
            endpoint,
            api_key,
            arguments.start,
            arguments.end,
            arguments.host_id,
            arguments.sequence,
            arguments.page_size,
            arguments.max_documents,
            certificate_path,
        )
        write_json(correlate_search_response(search_response), arguments.output)
    except (ReaderError, CorrelationError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
