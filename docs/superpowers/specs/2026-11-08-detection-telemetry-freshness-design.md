# Detection Telemetry Freshness Monitoring — Design

## Goal

Extend the existing read-only Detection Health Dashboard so each deployed Elastic detection reports both its rule-execution health and the availability/freshness of the telemetry sources it searches.

The feature is an operational visibility control. It does not establish detection coverage, fidelity, true-positive rate, or false-positive rate.

## Scope and boundaries

- Modify only `development/detection_health.py`, `development/build_detection_health_dashboard.py`, `tests/test_detection_health.py`, and `tests/test_detection_health_dashboard.py`.
- Reuse the existing `ELASTIC_HEALTH_KEY`, `ELASTIC_KIBANA_URL`, `ELASTICSEARCH_URL`, and `ELASTIC_SECURITY_SPACE` configuration.
- Do not change detection TOMLs, deployment code, deployment workflows, GitHub Actions workflows, Elastic rules, or API credentials.
- Make only read-only Elasticsearch requests.
- Store and publish aggregate telemetry health data only. Never include event documents, host identifiers, usernames, command lines, endpoint URLs, authorization headers, or API keys.
- Retain schema version `1`; telemetry is an optional additive property so historical snapshots remain usable.

## Collection flow

1. List deployed rules using the existing Kibana Detection Engine rule endpoint.
2. Extract each rule's `index` list.
3. Normalize and validate each individual index pattern. A pattern is safe only when it is a single, non-empty Elasticsearch-style pattern using a constrained allowlist of index-name characters and wildcard characters. Empty patterns, `_all`, comma-separated groups, whitespace, remote-cluster syntax, date math, and path/query characters are not sent to Elasticsearch.
4. Capture one UTC assessment timestamp for the collection run.
5. Build a cache keyed by normalized pattern and the effective telemetry configuration, including the threshold and fixed assessment window start.
6. For each unique safe pattern, resolve matching indices, aliases, or data streams using the Elasticsearch Resolve Index API.
7. If it resolves, perform one bounded aggregation-only Search API request. The request uses `size: 0` and has no `_source`, stored fields, or hits.
8. Attach the cached pattern assessments to all referencing rules and calculate a separate per-rule telemetry rollup.
9. Write the normal reports and snapshot only after existing alert-activity safety requirements remain satisfied. Telemetry request failures are represented as `UNAVAILABLE`, never converted to zero events.

## Elasticsearch APIs and permissions

### Resolve source availability

```http
GET /_resolve/index/<encoded-pattern>?expand_wildcards=open&allow_no_indices=true&ignore_unavailable=true
```

An empty successful resolution confirms `MISSING`. A 403, timeout, malformed response, or non-index-not-found error is `UNAVAILABLE`.

Required privilege: `view_index_metadata` on the permitted telemetry patterns.

### Aggregate telemetry freshness

```http
POST /<encoded-pattern>/_search
{
  "size": 0,
  "track_total_hits": false,
  "aggs": {
    "latest_ingested": {
      "max": {
        "field": "event.ingested",
        "format": "strict_date_optional_time"
      }
    },
    "latest_timestamp": {
      "max": {
        "field": "@timestamp",
        "format": "strict_date_optional_time"
      }
    },
    "recent_ingested": {
      "filter": {
        "range": {
          "event.ingested": {
            "gte": "<fixed-assessment-time-minus-threshold>"
          }
        }
      }
    },
    "recent_timestamp": {
      "filter": {
        "range": {
          "@timestamp": {
            "gte": "<fixed-assessment-time-minus-threshold>"
          }
        }
      }
    }
  }
}
```

The selected timestamp field determines the recent-event-count bucket. `event.ingested` is selected when its maximum timestamp is valid. `@timestamp` is used only when no valid `event.ingested` maximum is available.

Required privilege: `read` on the permitted telemetry patterns.

Every search response must have `timed_out: false`, no failed shards, and complete required aggregation structures before it is accepted.

## Configuration

`ELASTIC_TELEMETRY_FRESHNESS_SECONDS` configures the global operational freshness threshold.

- Default: `86400` seconds (24 hours).
- It must be a positive integer; invalid, zero, or negative values fail configuration validation before collection.
- The collector calculates one absolute UTC window start from the run's assessment timestamp. This produces deterministic results for all patterns in that run.

The threshold is a default operational heuristic. It is intentionally not interpreted as detection effectiveness or an assumption that every source emits continuously. Future work may add explicit source-specific thresholds without changing the snapshot model.

## Classification

| Status | Conditions |
| --- | --- |
| `FRESH` | Source resolves and the selected valid latest timestamp is within the effective threshold. |
| `STALE` | Source resolves and the selected valid latest timestamp is older than the effective threshold. |
| `MISSING` | Resolve API confirms no matching index, alias, or data stream. |
| `UNAVAILABLE` | Permissions, network/API failure, timeout, shard failure, malformed API response, or another retrieval failure prevents a reliable result. |
| `UNKNOWN` | Source exists but lacks sufficient valid timestamp evidence, including an empty source or invalid/missing timestamp aggregation values. |
| `NOT_ASSESSED` | A historical snapshot lacks telemetry fields, a rule has no usable index patterns, or a pattern is intentionally rejected before querying. |

Recent event count is always recorded independently of the freshness classification when it can be reliably calculated. A zero count is never converted into a detection failure.

## Per-pattern and per-rule model

Each live rule-health row receives a telemetry structure:

```json
{
  "status": "FRESH",
  "assessed_at": "2026-11-08T14:00:00Z",
  "freshness_threshold_seconds": 86400,
  "patterns": [
    {
      "index_pattern": "logs-windows.sysmon_operational-*",
      "status": "FRESH",
      "assessed_at": "2026-11-08T14:00:00Z",
      "freshness_threshold_seconds": 86400,
      "timestamp_field": "event.ingested",
      "last_event_timestamp": "2026-11-08T13:55:12Z",
      "recent_event_count": 281
    }
  ]
}
```

Only the listed aggregate fields are written. Error text is kept short and generic; it must not include credentials, endpoint URLs, or response document content.

For a rule with multiple source patterns, every result remains visible. The rollup is `FRESH` only when every assessed pattern is fresh. Otherwise, `UNAVAILABLE`, `MISSING`, `STALE`, and `UNKNOWN` take precedence in that order. This prevents one fresh input from hiding an unavailable or stale input.

Rule execution status remains exactly as it is today. A detection can therefore be execution `HEALTHY` and telemetry `STALE` at the same time.

## Historical compatibility and dashboard behavior

Existing historical snapshots are not rewritten. When the optional telemetry structure is absent, the dashboard displays `NOT_ASSESSED` and does not infer source state.

The dashboard will add:

- A telemetry-health status to each inventory row.
- Latest timestamp, selected timestamp field, recent aggregate event count, and threshold in the detail view.
- A telemetry-concerns review group containing `STALE`, `MISSING`, `UNAVAILABLE`, and `UNKNOWN` rules.
- A limitation explaining the telemetry threshold and the distinction from detection effectiveness.

Dashboard construction continues to use escaped JSON and `textContent`; telemetry values are treated as untrusted data.

## Error handling

- Unsupported patterns are never sent to Elasticsearch and are represented as `NOT_ASSESSED` with a non-sensitive reason code.
- 403 responses are `UNAVAILABLE`, never `MISSING`.
- Resolve responses with no matched resource are `MISSING`.
- Search timeouts, partial shard failures, connection failures, non-200 responses, and malformed responses are `UNAVAILABLE`.
- Empty resolved sources and absent/invalid timestamp values are `UNKNOWN`.
- A telemetry collection failure does not fabricate a zero count or reuse an earlier value as if it were current.

## Tests

Mocked tests will cover:

- `FRESH`, `STALE`, `MISSING`, `UNAVAILABLE`, `UNKNOWN`, and historical `NOT_ASSESSED` display.
- `event.ingested` preference and valid `@timestamp` fallback.
- Empty sources, malformed timestamp values, HTTP 403, connection timeout, timed-out search, partial shard failure, and malformed resolve/search data.
- Positive-integer threshold validation.
- Multiple pattern retention and worst-status rollup.
- One resolve/search assessment per unique normalized pattern and effective freshness configuration.
- Dashboard rendering of telemetry detail, review queue, and historical snapshot compatibility.

All existing mocked tests, offline detection fixtures, TOML validation, and MITRE validation remain regression checks.
