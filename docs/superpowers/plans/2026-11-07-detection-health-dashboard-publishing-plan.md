# Detection Health Dashboard Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use inline execution task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one secure GitHub Actions workflow that tests, refreshes, and publishes the static Detection Health Dashboard through GitHub Pages.

**Architecture:** The existing collector creates health reports and the existing generator creates the static dashboard. The new workflow selects live collection only for scheduled/manual live runs, uses historical data for PR and manual demo runs, packages a sanitized `_site` directory, and deploys it only from authorized `main` runs.

**Tech Stack:** Python standard library, existing `requests` collector, GitHub Actions, GitHub Pages official actions.

**Spec:** `docs/superpowers/specs/2026-11-07-detection-health-dashboard-publishing-design.md`

## Global Constraints

- Do not modify detection TOMLs, `elastic_sync.yml`, deployment scripts, or repository visibility.
- Do not access Elastic credentials, run workflows, commit, push, merge, or publish Pages locally.
- Scheduled runs use 09:00 `America/New_York`; scheduled/manual `live` collection uses read-only secrets only in its collection step.
- Pull requests have no Elastic secrets and never deploy Pages.
- The public site has only `index.html`, CSS, and JavaScript; it must not publish raw snapshots, endpoints, credentials, raw events, host identifiers, or alert documents.
- The final Phase 2 PR must target `main` only after Phase 1 has merged there.

---

### Task 1: Add Pages-site output and validation

**Files:**
- Modify: `development/build_detection_health_dashboard.py`
- Modify: `tests/test_detection_health_dashboard.py`

**Interfaces:**
- `generate_pages_site(model: dict, site_directory: Path) -> dict[str, Path]` writes `index.html`, CSS, and JS.
- `validate_pages_site(site_directory: Path) -> None` enforces the exact asset set and fails on sensitive markers.
- CLI option `--site-directory PATH` writes the normal Phase 1 reports plus a deployable site directory.

- [ ] Add failing tests asserting the site asset names, the absence of snapshot JSON, and rejection of a file containing `Authorization:` or `elastic.cloud`.
- [ ] Implement `generate_pages_site()` by reusing the existing HTML/CSS/JS generator content with `index.html` as the public HTML name.
- [ ] Implement `validate_pages_site()` with standard-library directory inspection and marker scanning; reject missing assets, unexpected files, and sensitive markers.
- [ ] Add `--site-directory` parsing and invoke both generation and validation only after a dashboard model is built successfully.
- [ ] Run `python -m unittest tests/test_detection_health_dashboard.py`.

### Task 2: Cover live-configuration failure before requests

**Files:**
- Modify: `tests/test_detection_health.py`

**Interfaces:**
- `required_environment()` remains the collector gate and raises `HealthMonitorError` when any required secret/configuration value is absent.

- [ ] Add a failing test with an empty environment asserting `required_environment()` lists required missing names.
- [ ] Run `python -m unittest tests/test_detection_health.py` and verify no requests are made by this test path.

### Task 3: Add one workflow with separate build/deploy jobs

**Files:**
- Create: `.github/workflows/detection_health_dashboard.yml`
- Create: `tests/test_dashboard_workflow.py`

**Interfaces:**
- Workflow inputs: `mode` choice with `live` default and `demo` option.
- Build mode: PR -> demo, schedule -> live, manual -> selected input.
- Deploy job: depends on build and is limited to scheduled/manual runs on `refs/heads/main`.

- [ ] Add standard-library workflow text tests asserting no `ELASTIC_*` secret appears in PR-only logic, deploy is main-only, `elastic_sync.yml` is not called, and the official Pages actions are present.
- [ ] Write the workflow with timezone-aware daily schedule, PR path triggers, and manual dispatch input.
- [ ] Build job: checkout with persisted credentials disabled, set up Python, install `requests`, choose mode, run health/dashboard tests, live collect only in live mode, build `_site`, validate it, upload Pages artifact.
- [ ] Deploy job: minimal Pages permissions, `github-pages` environment, `configure-pages`, then `deploy-pages`; no Elastic secrets.
- [ ] Run `python -m unittest tests/test_dashboard_workflow.py`.

### Task 4: Document and run local regression checks

**Files:**
- Modify: `README.md`

**Interfaces:**
- README commands for `workflow_dispatch` live/demo modes, local site builds, and Pages configuration.

- [ ] Document all four required repository secrets, Pages source setting, schedule delay caveat, PR behavior, manual live/demo distinction, and the Phase 1-before-Phase 2 PR sequence.
- [ ] Run dashboard tests, health tests, workflow tests, full mocked test discovery, TOML validation, offline fixture tests, and Python syntax compilation.
- [ ] Run `git diff --check`; confirm `elastic_sync.yml` and detection TOMLs remain unchanged.
- [ ] Do not commit, push, merge, run a GitHub workflow, use secrets, connect to Elastic, or publish Pages.
