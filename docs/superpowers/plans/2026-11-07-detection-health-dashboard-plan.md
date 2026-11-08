# Detection Health Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use inline execution task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local, static Detection Health Dashboard from repository TOML metadata and an offline October 19 health-report snapshot.

**Architecture:** Extend the existing health collector to produce a schema-versioned JSON snapshot from the same collected rows as CSV and Markdown. A focused generator reads either that JSON or converts the existing CSV/Markdown snapshot, merges it with TOML metadata by stable `rule_id`, and emits a static, escaped HTML/CSS/JavaScript dashboard without browser access to Elastic.

**Tech Stack:** Python standard library (`csv`, `html`, `json`, `tomllib`, `pathlib`, `unittest`), existing `requests` health collector, static HTML/CSS/JavaScript.

**Spec:** `docs/superpowers/specs/2026-11-07-detection-health-dashboard-design.md`

## Global Constraints

- Keep all development and tests local on `feature/detection-health-dashboard`.
- Do not change detection TOMLs, queries, deployment scripts, or `elastic_sync.yml` authorization behavior.
- Do not access live Elastic, use credentials, commit, push, merge, open a PR, or publish to GitHub Pages.
- Use only a saved October 19 health report for the initial dashboard generation.
- Keep operational health, deployment state, alert activity, validation health, and effectiveness as separate dimensions.
- Use `textContent` for browser-rendered data and safely embed JSON so untrusted content cannot terminate a script tag.
- Preserve terminal reporting plus existing CSV/Markdown health reports.

---

## File Structure

- Modify `development/detection_health.py`: remove hardcoded environment overrides and add a JSON snapshot serializer/writer that uses the same rows and timestamp as existing reports.
- Create `development/build_detection_health_dashboard.py`: load health JSON or convert existing CSV/Markdown reports, load TOML metadata, correlate rules, generate escaped static dashboard assets.
- Modify `tests/test_detection_health.py`: test JSON schema and safe atomic report bundle behavior.
- Create `tests/test_detection_health_dashboard.py`: test offline conversion, metrics, identity matching, unavailable states, escaping, and generated HTML markers.
- Create `reports/detection_health_snapshot.json`: generated, versioned historical snapshot from October 19 CSV/Markdown reports.
- Create `reports/detection_health_dashboard.html`, `.css`, `.js`: generated static local dashboard.
- Modify `README.md`: document local dashboard build/view/test commands and lab limitations.

### Task 1: Secure and structure the health snapshot

**Files:**
- Modify: `development/detection_health.py`
- Modify: `tests/test_detection_health.py`

**Interfaces:**
- Produces `health_snapshot(rows, lookback, generated_at, collection_status)` returning a JSON-serializable dictionary.
- Produces `write_audit_reports(..., reports_directory=...)` that writes CSV, Markdown, and JSON only after all content has been prepared.

- [ ] Write tests asserting that a snapshot contains `schema_version`, generation timestamp, lookback, inventory, summary metrics, duplicate candidates, and unavailable alert data without converting it to zero.
- [ ] Add `health_snapshot()` using existing `summary_metrics()` and full rows; preserve UUIDs and alert availability.
- [ ] Remove assignments that overwrite `ELASTIC_KIBANA_URL`, `ELASTICSEARCH_URL`, and `ELASTIC_SECURITY_SPACE`; leave environment validation in place.
- [ ] Extend report writing to prepare CSV, Markdown, and pretty JSON before replacing any report file, then write each target using the existing temporary-file replacement approach.
- [ ] Run `python tests/test_detection_health.py` and confirm current terminal/report behavior remains covered.

### Task 2: Build an offline data model and dashboard generator

**Files:**
- Create: `development/build_detection_health_dashboard.py`
- Create: `tests/test_detection_health_dashboard.py`

**Interfaces:**
- `load_snapshot(path: Path) -> dict` validates structured JSON.
- `convert_legacy_reports(csv_path: Path, markdown_path: Path) -> dict` creates an explicitly historical snapshot when JSON is unavailable.
- `load_repository_rules(detections_directory: Path) -> list[dict]` reads TOML metadata without changing it.
- `correlate_rules(repository_rules: list[dict], snapshot_rows: list[dict]) -> dict` returns matched, repository-only, and elastic-only rule records keyed by stable `rule_id`.
- `dashboard_model(snapshot: dict, repository_rules: list[dict]) -> dict` derives display-only metrics and sections.
- `generate_dashboard(model: dict, output_directory: Path) -> list[Path]` writes the static assets.

- [ ] Write tests using temporary CSV/TOML/JSON fixtures for stable-ID matching, duplicate display names with different UUIDs, zero-alert review flags, malformed CSV/JSON failure, unavailable alert activity, and no TP/FP fields.
- [ ] Parse CSV with `csv.DictReader`; obtain report timestamp/lookback from the Markdown header; mark conversion `source_kind: legacy_report_snapshot` and `is_live: false`.
- [ ] Read TOML with `tomllib`; extract rule ID, name, description, severity, risk score, type, index, and MITRE IDs. Raise a clear error for malformed TOML rather than silently omitting it.
- [ ] Correlate by `rule_id`. Never fall back to a display-name identity match. Put non-matches in explicit repository-only or Elastic-only collections.
- [ ] Generate one normalized model whose dimensions are separate: `deployment`, `operational_health`, `alert_activity`, `validation_health`, and `detection_effectiveness`.
- [ ] Run `python tests/test_detection_health_dashboard.py`.

### Task 3: Create safe responsive static assets

**Files:**
- Create: `reports/detection_health_dashboard.html`
- Create: `reports/detection_health_dashboard.css`
- Create: `reports/detection_health_dashboard.js`
- Modify: `development/build_detection_health_dashboard.py`

**Interfaces:**
- The generator writes a JSON payload into `<script type="application/json" id="dashboard-data">` after replacing `<` with `\\u003c`, `>` with `\\u003e`, and `&` with `\\u0026`.
- JavaScript reads `dashboard-data`, renders rule content with `document.createElement()` and `textContent`, and never assigns untrusted values with `innerHTML`.

- [ ] Write tests proving a TOML/snapshot name containing `<script>` is escaped in generated HTML and cannot become executable markup.
- [ ] Create HTML structure for header, snapshot-status banner, summary cards, controls, inventory table, detail panel, and review sections.
- [ ] Create dark responsive CSS using CSS custom properties and semantic status colors with text labels; preserve usability on narrow windows.
- [ ] Create JavaScript table search, sort, filters, detail rendering, and dynamic snapshot-age calculation from `generated_at` using `Date.now()`.
- [ ] Use `textContent` for names, descriptions, identifiers, flags, and details; no `innerHTML` for untrusted data.
- [ ] Run dashboard tests and inspect the generated files for endpoint URLs, API keys, Authorization strings, TP/FP claims, and execution of embedded input.

### Task 4: Generate the October 19 historical dashboard and document it

**Files:**
- Create: `reports/detection_health_snapshot.json`
- Create: `reports/detection_health_dashboard.html`
- Create: `reports/detection_health_dashboard.css`
- Create: `reports/detection_health_dashboard.js`
- Modify: `README.md`

**Interfaces:**
- CLI: `python development/build_detection_health_dashboard.py --from-legacy-reports --reports-directory reports`.
- CLI: `python development/build_detection_health_dashboard.py --snapshot reports/detection_health_snapshot.json --reports-directory reports`.

- [ ] Generate a structured snapshot offline from the existing October 19 CSV/Markdown reports.
- [ ] Generate static assets from that snapshot; label it as historical and calculate its age dynamically in the browser.
- [ ] Update README with what the dashboard does/does not measure, local commands, testing commands, snapshot freshness behavior, credential requirements for later live collection, and confirmation this is an independent lab.
- [ ] Run `python -m py_compile development/detection_health.py development/build_detection_health_dashboard.py`.
- [ ] Run existing health, dashboard, offline detection, validation, MITRE, and deployment-adapter test commands; record outcomes without contacting Elastic.
- [ ] Open the local HTML through a local HTTP server or browser and manually verify search, filters, sorting, rule details, historical label, zero-alert handling, and responsive layout.

### Task 5: Local security and workflow review

**Files:**
- Review only: `.github/workflows/elastic_sync.yml`, `.github/workflows/toml_mitre_validation.yml`, generated dashboard assets.

- [ ] Confirm no workflow was changed and no dashboard path can trigger Elastic deployment.
- [ ] Search generated assets and source for `ApiKey`, `Authorization`, `ELASTIC_KEY`, and Elastic URLs; confirm none are emitted by dashboard generation.
- [ ] Confirm the collector now reads configuration only from environment variables and keeps credentials out of reports.
- [ ] Confirm `git diff --check` and `git status --short`; preserve `development/practice.py` and cache files untouched.
