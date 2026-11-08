# Detection Telemetry Freshness Monitoring Implementation Plan

> **For agentic workers:** Execute this plan task-by-task with focused test runs after each task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only, cached Elastic telemetry availability and freshness assessments to the existing Detection Health Dashboard without changing execution-health behavior or deployment infrastructure.

**Architecture:** The collector will extract safe source patterns from deployed Kibana detection rules, resolve each distinct pattern once, and issue one aggregation-only search per resolved pattern. Per-pattern aggregate assessments are cached, attached to all referencing rule rows, written as optional snapshot data, and rendered as a telemetry-health dimension independent of rule execution and alert activity.

**Tech Stack:** Python standard library, existing `requests` dependency, Elasticsearch Resolve Index API and Search API, existing static HTML/CSS/JavaScript dashboard, `unittest` mocks.

**Spec:** `docs/superpowers/specs/2026-11-08-detection-telemetry-freshness-design.md`

## Global Constraints

- Keep all Elasticsearch requests read-only and bounded; search requests use `size: 0` and aggregations only.
- Use existing `ELASTIC_HEALTH_KEY`, `ELASTIC_KIBANA_URL`, `ELASTICSEARCH_URL`, and `ELASTIC_SECURITY_SPACE` configuration unchanged.
- Add `ELASTIC_TELEMETRY_FRESHNESS_SECONDS`, defaulting to the positive integer `86400`.
- Never retrieve or publish raw telemetry documents, endpoint URLs, credentials, headers, host identifiers, user identifiers, or command lines.
- Preserve existing execution status and alert metrics unchanged; telemetry is a separate optional field.
- Retain snapshot schema version `1` and render historical snapshots with absent telemetry as `NOT_ASSESSED`.
- Do not modify detection TOMLs, `development/update_alert.py`, `.github/workflows/elastic_sync.yml`, or `.github/workflows/detection_health_dashboard.yml`.
- Do not access live Elastic, use credentials, commit, push, merge, or deploy.

---

### Task 1: Build the test-first telemetry assessment primitives

**Files:**
- Modify: `development/detection_health.py:15-250`
- Modify: `tests/test_detection_health.py:1-168`

**Interfaces:**
- Consumes: existing `requests.Session`, `api_headers()`, `response_json()`, `response_detail()`, and UTC `datetime` values.
- Produces:
  - `telemetry_freshness_seconds(environment=os.environ) -> int`
  - `normalize_index_pattern(value) -> str | None`
  - `telemetry_resolve_url(elasticsearch_url, pattern) -> str`
  - `telemetry_aggregation_body(window_start) -> dict`
  - `assess_index_pattern(session, elasticsearch_url, headers, pattern, assessed_at, threshold_seconds) -> dict`

- [ ] **Step 1: Add failing classification and configuration tests**

Add compact fixture helpers in `tests/test_detection_health.py` that create Resolve Index and aggregation responses without documents:

```python
def resolved_source_response():
    return FakeResponse(200, {"indices": [{"name": "logs-test-000001", "attributes": ["open"]}], "aliases": [], "data_streams": []})

def telemetry_search_response(ingested=None, timestamp=None, ingested_count=0, timestamp_count=0):
    return FakeResponse(200, {
        "timed_out": False,
        "_shards": {"failed": 0},
        "aggregations": {
            "latest_ingested": {"value_as_string": ingested, "value": 1 if ingested else None},
            "latest_timestamp": {"value_as_string": timestamp, "value": 1 if timestamp else None},
            "recent_ingested": {"doc_count": ingested_count},
            "recent_timestamp": {"doc_count": timestamp_count},
        },
    })

def test_telemetry_uses_event_ingested_and_is_fresh(self):
    session = FakeSession(get_responses=[resolved_source_response()], post_responses=[telemetry_search_response(ingested="2026-10-18T11:55:00Z", timestamp="2026-10-18T10:00:00Z", ingested_count=12)])
    assessment = detection_health.assess_index_pattern(session, "https://es.example", {}, "logs-test-*", NOW, 86400)
    self.assertEqual(assessment["status"], "FRESH")
    self.assertEqual(assessment["timestamp_field"], "event.ingested")
    self.assertEqual(assessment["recent_event_count"], 12)
```

Also add focused tests for `STALE`, `MISSING`, `UNKNOWN` empty source, malformed timestamps, `403`, `requests.Timeout`, `timed_out: true`, failed shards, malformed Resolve Index payload, malformed aggregation payload, and `ELASTIC_TELEMETRY_FRESHNESS_SECONDS` values `"0"`, `"-1"`, and `"not-a-number"`.

- [ ] **Step 2: Run the focused tests to confirm they fail before implementation**

Run:

```powershell
python -m unittest tests/test_detection_health.py
```

Expected: failures or errors identify the missing telemetry helpers.

- [ ] **Step 3: Add safe pattern, threshold, endpoint, and body helpers**

In `development/detection_health.py`, define constants next to current collector constants:

```python
DEFAULT_TELEMETRY_FRESHNESS_SECONDS = 86400
SAFE_INDEX_PATTERN_RE = re.compile(r"^[a-z0-9._*?-]+$")
```

Implement the helper behavior exactly:

```python
def telemetry_freshness_seconds(environment=os.environ):
    raw = environment.get("ELASTIC_TELEMETRY_FRESHNESS_SECONDS", str(DEFAULT_TELEMETRY_FRESHNESS_SECONDS))
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise HealthMonitorError("ELASTIC_TELEMETRY_FRESHNESS_SECONDS must be a positive integer") from error
    if value <= 0:
        raise HealthMonitorError("ELASTIC_TELEMETRY_FRESHNESS_SECONDS must be a positive integer")
    return value

def normalize_index_pattern(value):
    if not isinstance(value, str):
        return None
    pattern = value.strip().casefold()
    if not pattern or pattern in {"*", "_all"} or not SAFE_INDEX_PATTERN_RE.fullmatch(pattern):
        return None
    return pattern
```

Use `quote(pattern, safe="*._-")` in the Resolve Index and Search URL path builders. The literal `?` wildcard must be percent-encoded so it cannot become a URL query delimiter. The aggregation body must include only `size: 0`, `track_total_hits: false`, two `max` aggregations, and two filter aggregations using the fixed UTC `window_start` text.

- [ ] **Step 4: Implement one safe per-pattern read-only assessment**

`assess_index_pattern()` must:

1. Reject a `None` normalized pattern without any request and return `NOT_ASSESSED` with a reason code.
2. Call Resolve Index once with `expand_wildcards=open`, `allow_no_indices=true`, and `ignore_unavailable=true`.
3. Return `MISSING` only for an empty, valid, successful resolution or an explicit `index_not_found_exception`; return `UNAVAILABLE` for 403 and every other failed/invalid availability response.
4. Call Search once only after a non-empty resolution.
5. Reject a search response with `timed_out is not False`, any positive failed-shard count, or missing aggregation structures as `UNAVAILABLE`.
6. Select a parseable `event.ingested` maximum first; otherwise select a parseable `@timestamp` maximum. If neither is valid, return `UNKNOWN` and preserve the available count only when its selected aggregation is structurally valid.
7. Compare the chosen timestamp with `assessed_at - timedelta(seconds=threshold_seconds)` to select `FRESH` or `STALE`.
8. Return only `index_pattern`, `status`, `assessed_at`, `freshness_threshold_seconds`, `timestamp_field`, `last_event_timestamp`, `recent_event_count`, and an optional short reason code.

Use `requests.RequestException` handling and generic reason codes such as `RESOLVE_HTTP_403`, `SEARCH_TIMEOUT`, and `SEARCH_SHARD_FAILURE`; do not copy Elastic response bodies into telemetry rows.

- [ ] **Step 5: Run focused tests and syntax check**

Run:

```powershell
python -m py_compile development/detection_health.py
python -m unittest tests/test_detection_health.py
```

Expected: all existing health-monitor tests plus new primitive tests pass.

### Task 2: Cache and attach telemetry assessments to live rule rows

**Files:**
- Modify: `development/detection_health.py:251-665`
- Modify: `tests/test_detection_health.py:169-330`

**Interfaces:**
- Consumes: `assess_index_pattern()`, deployed rule documents returned by `get_rules()`, and one run-level `assessed_at` UTC timestamp.
- Produces:
  - `collect_rule_telemetry(session, elasticsearch_url, headers, rules, assessed_at, threshold_seconds) -> dict[str, dict]`
  - `telemetry_rollup(patterns, assessed_at, threshold_seconds) -> dict`
  - extended `build_rows(..., telemetry_by_rule=None)` rows with `telemetry`.

- [ ] **Step 1: Add failing cache, multiple-pattern, and rollup tests**

Add rule helper data with `index` lists and tests that verify:

```python
def test_reused_index_pattern_is_assessed_once(self):
    first = dict(rule(), id="first", index=["logs-shared-*"])
    second = dict(rule(), id="second", index=[" LOGS-SHARED-* "])
    telemetry = detection_health.collect_rule_telemetry(session, "https://es.example", {}, [first, second], NOW, 86400)
    self.assertEqual(len(session.get_calls), 1)
    self.assertEqual(len(session.post_calls), 1)
    self.assertEqual(telemetry["first"]["patterns"], telemetry["second"]["patterns"])
```

Add a multi-pattern test where one pattern is FRESH and another is STALE; assert the rule rollup is `STALE` and both pattern results remain present. Add separate tests asserting precedence for `UNAVAILABLE`, `MISSING`, and `UNKNOWN`, and that a missing `index` field yields `NOT_ASSESSED`.

- [ ] **Step 2: Run focused tests to confirm the collection/rollup API is absent**

Run:

```powershell
python -m unittest tests/test_detection_health.py
```

Expected: failures identify `collect_rule_telemetry`, `telemetry_rollup`, or the absent row field.

- [ ] **Step 3: Implement cached collection and conservative rollups**

Use a run-local cache keyed by:

```python
(normalized_pattern, threshold_seconds, generation_timestamp(assessed_at))
```

For each rule, retain a result for every declared source pattern in input order. A rejected pattern creates a `NOT_ASSESSED` result but is not sent to Elasticsearch. Do not collapse source-pattern entries merely because their normalized cache key is shared.

Implement the rule rollup using this explicit precedence:

```python
TELEMETRY_STATUS_PRECEDENCE = ("UNAVAILABLE", "MISSING", "STALE", "UNKNOWN")

def telemetry_rollup(patterns, assessed_at, threshold_seconds):
    if not patterns:
        return {"status": "NOT_ASSESSED", "assessed_at": generation_timestamp(assessed_at), "freshness_threshold_seconds": threshold_seconds, "patterns": []}
    for status in TELEMETRY_STATUS_PRECEDENCE:
        if any(pattern["status"] == status for pattern in patterns):
            return {"status": status, "assessed_at": generation_timestamp(assessed_at), "freshness_threshold_seconds": threshold_seconds, "patterns": patterns}
    if all(pattern["status"] == "FRESH" for pattern in patterns):
        return {"status": "FRESH", "assessed_at": generation_timestamp(assessed_at), "freshness_threshold_seconds": threshold_seconds, "patterns": patterns}
    return {"status": "NOT_ASSESSED", "assessed_at": generation_timestamp(assessed_at), "freshness_threshold_seconds": threshold_seconds, "patterns": patterns}
```

Extend `build_rows()` with a final optional `telemetry_by_rule=None` parameter so all old tests/callers retain their behavior. For live collection, set each row's `telemetry` from its UUID mapping; for old callers or historical conversions, use a `NOT_ASSESSED` structure without inventing telemetry values. Add `TELEMETRY_<STATUS>` to `review_flags` only for `STALE`, `MISSING`, `UNAVAILABLE`, or `UNKNOWN`.

- [ ] **Step 4: Integrate telemetry collection into the existing main flow**

In `required_environment()`, add `telemetry_freshness_seconds()` to the returned configuration. In `main()`, set `generated_at = datetime.now(timezone.utc)` once after rules and alert activity are safely collected, then call:

```python
telemetry_by_rule = collect_rule_telemetry(
    session,
    config["elasticsearch_url"],
    headers,
    rules,
    generated_at,
    config["telemetry_freshness_seconds"],
)
```

Pass `telemetry_by_rule` into `build_rows()`. Do not turn a telemetry `UNAVAILABLE` assessment into an alert error or abort report generation; it is a current observation that belongs in the snapshot. Preserve the existing behavior that an unavailable alert aggregation prevents overwriting reports.

- [ ] **Step 5: Preserve snapshot/report compatibility**

Keep `SNAPSHOT_SCHEMA_VERSION = 1`. `health_snapshot()` should carry the extended rows unchanged, so telemetry is optional in old and new snapshot inventory data. Do not alter the legacy CSV required columns. Extend Markdown findings only with a telemetry limitation/follow-up statement if the current function can do so without changing its existing operational and alert calculations.

- [ ] **Step 6: Run collector regression tests**

Run:

```powershell
python -m py_compile development/detection_health.py
python -m unittest tests/test_detection_health.py
```

Expected: existing report safety tests continue to pass; telemetry failures are visible as telemetry statuses and never represented as zero recent events.

### Task 3: Render telemetry as a separate dashboard dimension

**Files:**
- Modify: `development/build_detection_health_dashboard.py:322-545`
- Modify: `tests/test_detection_health_dashboard.py:90-275`

**Interfaces:**
- Consumes: optional `health_row["telemetry"]` generated by the collector.
- Produces: `display_row()` values at `row["telemetry_health"]`, telemetry-aware `dashboard_model()` review sections, and dashboard JavaScript that renders telemetry by `textContent`.

- [ ] **Step 1: Add failing dashboard-model tests**

Add a live-like snapshot inventory row containing:

```python
"telemetry": {
    "status": "STALE",
    "assessed_at": TIMESTAMP,
    "freshness_threshold_seconds": 86400,
    "patterns": [{
        "index_pattern": "logs-windows.sysmon_operational-*",
        "status": "STALE",
        "timestamp_field": "event.ingested",
        "last_event_timestamp": "2026-10-17T00:00:00Z",
        "recent_event_count": 0,
    }],
}
```

Assert that `dashboard_model()` preserves `STALE`, includes the rule in `review_sections["telemetry_concerns"]`, and does not change `operational_health`. Add a historical snapshot test that omits `telemetry` and expects `row["telemetry_health"]["status"] == "NOT_ASSESSED"`.

Add an HTML/JavaScript safety assertion that telemetry names with `<script>` are escaped by the existing safe JSON mechanism and rendered through `textContent`, not `innerHTML`.

- [ ] **Step 2: Run dashboard tests to establish the missing model and rendering behavior**

Run:

```powershell
python -m unittest tests/test_detection_health_dashboard.py
```

Expected: tests fail because the telemetry model and review section do not exist.

- [ ] **Step 3: Extend dashboard data model with a safe telemetry default**

Create a small helper near `display_row()`:

```python
def telemetry_display(health_row, deployed):
    telemetry = health_row.get("telemetry") if deployed else None
    if not isinstance(telemetry, dict):
        return {"status": "NOT_ASSESSED", "assessed_at": None, "freshness_threshold_seconds": None, "patterns": [], "note": "Telemetry was not assessed in this snapshot."}
    return {
        "status": telemetry.get("status", "UNKNOWN"),
        "assessed_at": telemetry.get("assessed_at"),
        "freshness_threshold_seconds": telemetry.get("freshness_threshold_seconds"),
        "patterns": telemetry.get("patterns") if isinstance(telemetry.get("patterns"), list) else [],
        "note": "",
    }
```

Set `display_row()["telemetry_health"]` from the helper. Add `telemetry_concerns` to `dashboard_model()["review_sections"]`; its statuses are exactly `STALE`, `MISSING`, `UNAVAILABLE`, and `UNKNOWN`. Do not put `NOT_ASSESSED` into this issue queue.

- [ ] **Step 4: Add telemetry to the static dashboard HTML and JavaScript**

Add one inventory-table column named `TELEMETRY` adjacent to operational health. In `renderRows()`, create a cell displaying `row.telemetry_health.status`. In `renderDetail()`, add fields for telemetry status, assessment time, threshold seconds, and one text-only per-pattern summary showing pattern, status, selected field, latest timestamp, and recent count. In `renderReviews()`, append a `Telemetry freshness concerns` group.

Use existing `element()`, `text()`, `clear()`, and `field()` helpers only. Do not introduce `innerHTML`, dynamic URL links, or new external assets. Add a dashboard limitation stating that freshness is a configurable ingestion-availability heuristic and does not prove detection effectiveness.

- [ ] **Step 5: Run dashboard tests and build a temporary public bundle**

Run:

```powershell
python -m unittest tests/test_detection_health_dashboard.py
$temporary = Join-Path $env:TEMP ('detection-telemetry-dashboard-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporary | Out-Null
python development/build_detection_health_dashboard.py --snapshot reports/detection_health_snapshot.json --reports-directory (Join-Path $temporary 'reports') --site-directory (Join-Path $temporary '_site')
Get-ChildItem (Join-Path $temporary '_site') | Select-Object -ExpandProperty Name
```

Expected: tests pass and the output contains only `index.html`, `detection_health_dashboard.css`, and `detection_health_dashboard.js`.

### Task 4: Execute the complete local regression suite and review the final diff

**Files:**
- Modify only the four files listed in Tasks 1–3.
- Preserve: all workflow, deployment, rule, and credential files.

**Interfaces:**
- Consumes: completed collector and dashboard changes.
- Produces: local test evidence only; no remote execution or deployment.

- [ ] **Step 1: Run syntax and every mocked unit test**

Run:

```powershell
python -m py_compile development/detection_health.py development/build_detection_health_dashboard.py
python -m unittest discover -s tests -p "test_*.py"
```

Expected: all test modules pass, including telemetry, dashboard, reader, correlator, publisher, deployment adapter, and workflow structural tests.

- [ ] **Step 2: Run existing offline detection validation**

Run:

```powershell
python tests/run_detection_tests.py
python development/validation1.py
python development/mitre.py
```

Expected: existing fixture matcher, TOML validation, and MITRE validation pass without changes to TOML rules.

- [ ] **Step 3: Review scope and retain local-only changes**

Run:

```powershell
git diff --check
git status --short
git diff -- development/detection_health.py development/build_detection_health_dashboard.py tests/test_detection_health.py tests/test_detection_health_dashboard.py
```

Expected: no whitespace errors; only the approved collector/dashboard/test files plus the specification and plan are changed. Do not commit, push, merge, call Elastic, trigger GitHub Actions, or publish GitHub Pages.

## Plan Self-Review

- Spec coverage: Tasks 1–2 cover read-only Resolve Index/Search collection, classifications, deterministic threshold configuration, caching, multiple patterns, error handling, and snapshot compatibility. Task 3 covers dashboard and public-data requirements. Task 4 covers regression validation and scope control.
- Placeholder scan: no deferred implementation markers or vague handling instructions remain; every task names the exact functions, inputs, outputs, tests, and commands.
- Type consistency: `telemetry_by_rule` is consistently a `dict[str, dict]`; each stored per-pattern result is consistently a dictionary; `build_rows(..., telemetry_by_rule=None)` preserves current callers; `telemetry_health` is the dashboard-facing display model.
