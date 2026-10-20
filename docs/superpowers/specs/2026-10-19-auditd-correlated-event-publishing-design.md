# Auditd Correlated Event Publishing Design

## Goal

Publish complete locally correlated auditd events to the dedicated `auditd-correlated-events` index without modifying the auditd source stream, the correlator, or an existing event.

## Input and document shape

`development/auditd_elastic_publisher.py` reads the JSON output produced by `development/auditd_correlator.py`. Each object in `correlated_events` is submitted unchanged as the Elasticsearch document body. It will not remove, rename, normalize, or add fields to `correlation_key`, `record_types`, `original_document_ids`, `source_records`, `merged`, `missing_record_types`, `conflicts`, or `duplicate_document_ids`.

## Identity and conflict handling

The document ID is `sha256` of canonical JSON containing only the complete correlation key: `host_id`, `timestamp`, and `auditd_log_sequence`. This creates the same identity for reruns but distinct identities across hosts, timestamps, and audit sequences.

The publisher uses `PUT /auditd-correlated-events/_create/{id}`. A `201` response is a new document. A `409` response causes a `GET` of the existing document. If its complete `_source` is canonically identical to the proposed correlated event, the result is `unchanged`. If it differs, the result is `conflict` and the publisher exits unsuccessfully without updating the existing document. This protects incomplete or late-arriving groups; resolving them needs an explicitly approved future workflow.

Multiple events are reported individually. The overall command fails if any event fails or conflicts; results make partial batches explicit.

## Index mapping and credentials

The target index must be manually created before publishing. The publisher will not auto-create it. The approved mapping maps the correlation key and small list fields for querying, sets root `dynamic` to `false`, and uses `enabled: false` for `source_records`, `merged`, and `conflicts`. Those fields remain complete in `_source` without dynamically indexing every original auditd field.

The publisher uses `ELASTIC_AUDITD_PUBLISH_URL`, `ELASTIC_AUDITD_PUBLISH_API_KEY`, and optional `ELASTIC_AUDITD_PUBLISH_CA_CERT`. Its API key is limited to `read` and `create_doc` on `auditd-correlated-events`; a separate setup identity creates the index and mapping. Credentials are never printed, persisted, or embedded in source.

## Safety and testing

Dry-run is the default and makes no HTTP request. Publishing requires an explicit `--publish` flag. HTTPS certificate validation uses Python's default SSL context. Standard-library mocked tests cover validation, deterministic IDs, dry-run isolation, mapping validation, successful creates, identical reruns, changed-document conflicts, index failures, HTTP errors, and partial batch results. Implementation and tests make no live Elasticsearch call.
