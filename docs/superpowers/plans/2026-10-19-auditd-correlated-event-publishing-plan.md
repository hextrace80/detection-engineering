# Auditd Correlated Event Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dry-run-first publisher that safely creates complete correlated auditd event documents in a dedicated Elasticsearch index.

**Architecture:** A standalone standard-library script reads the correlator's `correlated_events` output, validates each unmodified event, derives a SHA-256 ID from its correlation key, and uses Elasticsearch's create-only API. On a duplicate ID it compares the stored complete document and fails if it differs.

**Tech Stack:** Python standard library (`argparse`, `hashlib`, `json`, `ssl`, `urllib`), Elasticsearch REST APIs, `unittest` mocks.

**Spec:** `docs/superpowers/specs/2026-10-19-auditd-correlated-event-publishing-design.md`

## Global Constraints

- Preserve each correlated event unchanged as the Elasticsearch document body.
- The target is exactly `auditd-correlated-events`; never write to the auditd data stream.
- Default to dry-run; require `--publish` for HTTPS requests.
- Use environment variables for a dedicated API key and never print credentials.
- Never auto-create the index or overwrite a document.
- Do not modify the correlator, reader, ingest pipelines, GitHub workflows, or deployment code.

---

### Task 1: Publisher behavior and safe HTTP boundary

**Files:**
- Create: `development/auditd_elastic_publisher.py`
- Test: `tests/test_auditd_elastic_publisher.py`

**Interfaces:**
- Consumes: a JSON object with a `correlated_events` list from `auditd_correlator.py`.
- Produces: `publish_events(events, endpoint, api_key, publish, transport=None) -> list[dict]` outcomes with `created`, `unchanged`, `conflict`, or `failed` status.

- [ ] **Step 1: Write mocked tests** for canonical ID stability, exact body preservation, dry-run behavior, successful `_create`, identical rerun, changed-document conflict, missing index, and partial batches.
- [ ] **Step 2: Run focused tests** with `python tests/test_auditd_elastic_publisher.py` and observe the missing-module failure.
- [ ] **Step 3: Implement minimal publisher functions** using HTTPS, API-key headers, safe response errors, and `_create` plus GET comparison.
- [ ] **Step 4: Run focused tests** with `python tests/test_auditd_elastic_publisher.py` and verify all pass.

### Task 2: Index compatibility and command-line safety

**Files:**
- Modify: `development/auditd_elastic_publisher.py`
- Modify: `tests/test_auditd_elastic_publisher.py`

**Interfaces:**
- Consumes: `--input`, optional `--publish`, and publishing environment variables.
- Produces: terminal per-event outcomes, nonzero exit status on any failure, and a mapping JSON printer for separate index setup.

- [ ] **Step 1: Add mocked tests** for required mapping compatibility, absent or incompatible indices, environment validation, and no transport call during dry-run.
- [ ] **Step 2: Implement CLI and mapping check** so publish mode verifies the pre-created index mapping before any create request.
- [ ] **Step 3: Run regression tests** with `python tests/test_auditd_elastic_publisher.py`, `python tests/test_auditd_correlator.py`, and `python tests/test_auditd_elastic_reader.py`.
- [ ] **Step 4: Run syntax and whitespace checks** with `python -m py_compile development/auditd_elastic_publisher.py tests/test_auditd_elastic_publisher.py` and `git diff --check`.
