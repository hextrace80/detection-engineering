# Detection Health Dashboard Design

## Purpose

Create a static, portfolio-safe dashboard that presents the current Detection
Health & Metrics Audit snapshot together with repository-managed detection
metadata. The dashboard is a reporting surface, not a new detection deployment
or browser-based Elastic client.

## Scope and safety boundaries

- Build and test locally on `feature/detection-health-dashboard`.
- Reuse `development/detection_health.py` for health collection, health
  classifications, alert activity, duplicate-name candidates, and existing
  CSV/Markdown reports.
- Add a structured JSON snapshot from the same in-memory collection snapshot
  used for CSV and Markdown output.
- Generate static HTML, CSS, and JavaScript locally. The browser must never
  call Elastic or contain API keys, bearer tokens, or endpoint configuration.
- Use saved reports from October 19, 2026 when no live health collection is
  available. The UI must label this as a historical snapshot, including its
  generation timestamp and age.
- Do not change detection TOMLs, their queries, deployment scripts, or the
  authorization guard in `elastic_sync.yml`.
- Do not create a pull request, push, merge, publish to GitHub Pages, or use
  live Elastic credentials during this implementation.

## Inputs and correlation

The dashboard generator will accept a structured health JSON snapshot. It will
also read `detections/*.toml` using the Python standard library. Repository
rules correlate with deployed rules by stable `rule_id`; display name is never
the identity key. The output will show three inventories:

1. matched repository/deployed rules;
2. repository rules not represented in the deployed snapshot;
3. Elastic-only rules present in the health snapshot.

TOML metadata contributes name, description, severity, risk score, rule type,
index patterns, and MITRE technique/subtechnique identifiers. Health snapshot
data contributes UUID, enabled state, execution status/freshness, alert
activity, and review flags.

## Generated artifacts

The implementation will add a static dashboard directory below `reports/`:

- `reports/detection_health_snapshot.json` — schema-versioned health snapshot;
- `reports/detection_health_dashboard.html` — self-contained dashboard;
- `reports/detection_health_dashboard.css` — dark-theme styling;
- `reports/detection_health_dashboard.js` — client-side filtering, sorting,
  detail display, and table search.

The JSON includes `schema_version`, `generated_at`, `lookback`, collection
status, inventory records, summary metrics, and duplicate candidates. It
contains no alert document source, API responses, endpoint URLs, or secrets.

All dashboard content derived from TOML or snapshot data will be HTML-escaped.
The generated HTML will state that fixture checks are simulated Python adapters
unless a separately recorded real Elastic test result is available.

## Dashboard behavior

Summary cards will show repository-managed detection count; deployed total;
enabled/disabled; health-state counts; review count; and alert count or
`N/A` when alert activity is unavailable. The inventory table will provide:

- name, stable rule ID, deployed UUID, technique, severity, type;
- repository/deployment state, execution health, last execution;
- alert count and last alert; and
- review flags.

Controls will filter by execution health, severity, and technique, search
names/IDs, and sort table columns. A rule detail panel will explain its source
metadata, identity match state, operational signals, and review flags.

Dedicated panels will cover zero-alert enabled rules, execution concerns
(failed/degraded/stale), duplicate-name candidates, missing health data, and
available offline fixture results. Zero alerts are a review opportunity, not a
failure. The UI will use `Unknown`, `N/A`, or `Not assessed` rather than
inventing effectiveness, true-positive, or false-positive values.

## Health collector changes

`development/detection_health.py` will stop overriding environment variables.
It will require URLs and a dedicated read-only API key through its existing
environment configuration. Its existing terminal report and atomic CSV/Markdown
write behavior remain intact. JSON generation will prepare all report contents
before any replacement so an incomplete collection cannot replace a prior
complete report set.

## Test design

Extend `tests/test_detection_health.py` to cover structured JSON generation,
schema fields, and atomic write safety. Add dashboard-generator tests for:

- October 19 saved snapshot generation without Elastic credentials;
- metric calculations and unavailable alert activity;
- stable-ID matching and unmatched inventories;
- duplicate names distinguished by UUID;
- zero-alert and stale labels;
- malformed input safe failure;
- HTML escaping of untrusted TOML/snapshot values; and
- no fabricated TP/FP values.

Run current validation, offline detection, health-monitor, dashboard, and
deployment-adapter tests locally. Do not add Elastic KQL integration tests to
CI and do not call Elastic during tests.

## Workflow design (not implemented in this local-only phase)

A later dedicated dashboard workflow may build/test on relevant pull requests
and manually. Publishing may run only from an authorized main-branch workflow
and use GitHub Pages if explicitly enabled. It will not call `elastic_sync.yml`,
will not use deployment credentials, and will not commit generated files to
avoid workflow loops. Until publishing is approved, local static files are the
only deliverable.

## Limitations

The dashboard reports operational signals and repository validation evidence;
it does not measure detection efficacy. A successful rule run does not prove
coverage or malicious-behavior detection, and fixture tests do not execute
Elastic KQL. Historical snapshot data must never be represented as live data.
