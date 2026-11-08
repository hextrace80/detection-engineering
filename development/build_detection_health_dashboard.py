"""Build a static, credential-free Detection Health Dashboard.

The browser receives only a health-report snapshot and repository rule metadata.
It never contacts Elastic and does not embed endpoints or credentials.
"""

import argparse
import csv
import json
import re
import sys
import tomllib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORTS_DIRECTORY = REPOSITORY_ROOT / "reports"
DEFAULT_DETECTIONS_DIRECTORY = REPOSITORY_ROOT / "detections"
SNAPSHOT_FILENAME = "detection_health_snapshot.json"
DASHBOARD_HTML = "detection_health_dashboard.html"
DASHBOARD_CSS = "detection_health_dashboard.css"
DASHBOARD_JS = "detection_health_dashboard.js"
PAGES_INDEX = "index.html"
SNAPSHOT_SCHEMA_VERSION = 1
PUBLISHED_SITE_FILENAMES = {PAGES_INDEX, DASHBOARD_CSS, DASHBOARD_JS}
FORBIDDEN_PUBLISHED_MARKERS = (
    "authorization:",
    "apikey ",
    "elastic_health_key",
    "elastic_kibana_url",
    "elasticsearch_url",
    ".elastic.cloud",
)


class DashboardError(Exception):
    """Raised when dashboard input is incomplete or malformed."""


def utc_timestamp(value):
    """Return a normalized UTC timestamp string or raise a useful error."""
    if not isinstance(value, str):
        raise DashboardError("Snapshot generation timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DashboardError(f"Invalid snapshot generation timestamp: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_name(value):
    return " ".join(str(value).split()).casefold()


def snapshot_metrics(rows):
    """Calculate only observable operational metrics from health inventory rows."""
    status_counts = Counter(row["status"] for row in rows)
    enabled_rows = [row for row in rows if row["enabled"]]
    alert_available = not any(row.get("alert_error") for row in rows)
    alerting_enabled = []
    zero_alert_enabled = []
    total_alerts = None
    if alert_available:
        alerting_enabled = [
            row
            for row in enabled_rows
            if row["alert_activity"] is not None and row["alert_activity"]["count"] > 0
        ]
        zero_alert_enabled = [row for row in enabled_rows if row["alert_activity"] is None]
        total_alerts = sum(
            row["alert_activity"]["count"]
            for row in rows
            if row["alert_activity"] is not None
        )
    grouped = defaultdict(list)
    for row in rows:
        grouped[normalize_name(row["name"])].append(row)
    duplicates = [
        [row["uuid"] for row in group]
        for group in grouped.values()
        if len(group) > 1
    ]
    return {
        "total": len(rows),
        "enabled": len(enabled_rows),
        "disabled": len(rows) - len(enabled_rows),
        "healthy_enabled": sum(row["status"] == "HEALTHY" for row in enabled_rows),
        "status_counts": dict(status_counts),
        "alert_available": alert_available,
        "alerting_enabled_count": len(alerting_enabled),
        "zero_alert_enabled_count": len(zero_alert_enabled),
        "total_alerts": total_alerts,
        "duplicate_candidates": duplicates,
    }


def parse_legacy_row(record):
    required = {
        "Rule name",
        "Stable rule_id",
        "Elastic internal UUID",
        "Enabled state",
        "Health classification",
        "Rule type",
        "Execution interval",
        "Last execution time",
        "Last execution status",
        "Alert count for selected lookback",
        "Most recent alert timestamp",
        "Review flags",
    }
    missing = sorted(required - set(record))
    if missing:
        raise DashboardError(f"Legacy inventory CSV is missing columns: {', '.join(missing)}")

    count_text = record["Alert count for selected lookback"].strip()
    alert_error = None
    alert_activity = None
    if count_text == "UNAVAILABLE":
        alert_error = "Legacy snapshot reports alert activity as unavailable"
    else:
        try:
            count = int(count_text or "0")
        except ValueError as error:
            raise DashboardError(f"Invalid alert count in legacy inventory: {count_text}") from error
        if count < 0:
            raise DashboardError("Legacy inventory contains a negative alert count")
        if count:
            alert_activity = {
                "count": count,
                "last_alert": record["Most recent alert timestamp"].strip() or None,
            }

    enabled_text = record["Enabled state"].strip().casefold()
    if enabled_text not in {"enabled", "disabled"}:
        raise DashboardError(f"Invalid enabled state in legacy inventory: {enabled_text}")
    flags = [flag.strip() for flag in record["Review flags"].split(";") if flag.strip()]
    return {
        "name": record["Rule name"],
        "rule_id": record["Stable rule_id"],
        "uuid": record["Elastic internal UUID"],
        "enabled": enabled_text == "enabled",
        "type": record["Rule type"],
        "interval": record["Execution interval"],
        "status": record["Health classification"],
        "execution": {
            key: value
            for key, value in {
                "date": record["Last execution time"].strip() or None,
                "status": record["Last execution status"].strip() or None,
            }.items()
            if value is not None
        },
        "alert_activity": alert_activity,
        "alert_error": alert_error,
        "review_flags": flags,
    }


def legacy_report_metadata(summary_text):
    generated_match = re.search(r"^Generated:\s*(.+?)\s*$", summary_text, re.MULTILINE)
    lookback_match = re.search(r"^Alert lookback:\s*`([^`]+)`\s*$", summary_text, re.MULTILINE)
    if not generated_match or not lookback_match:
        raise DashboardError("Legacy Markdown summary is missing Generated or Alert lookback metadata")
    return utc_timestamp(generated_match.group(1)), lookback_match.group(1)


def convert_legacy_reports(csv_path, markdown_path):
    """Create an explicitly historical structured snapshot from existing reports."""
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as file:
            records = list(csv.DictReader(file))
    except FileNotFoundError as error:
        raise DashboardError(f"Legacy inventory CSV was not found: {csv_path}") from error
    if not records:
        raise DashboardError("Legacy inventory CSV contains no rule rows")
    timestamps = {utc_timestamp(record.get("Report generation timestamp")) for record in records}
    if len(timestamps) != 1:
        raise DashboardError("Legacy inventory CSV contains inconsistent report generation timestamps")
    try:
        summary_text = markdown_path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise DashboardError(f"Legacy Markdown summary was not found: {markdown_path}") from error
    summary_timestamp, lookback = legacy_report_metadata(summary_text)
    csv_timestamp = timestamps.pop()
    if csv_timestamp != summary_timestamp:
        raise DashboardError("Legacy CSV and Markdown reports have different generation timestamps")

    rows = [parse_legacy_row(record) for record in records]
    metrics = snapshot_metrics(rows)
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "generated_at": csv_timestamp,
        "lookback": lookback,
        "collection": {
            "source_kind": "legacy_report_snapshot",
            "is_live": False,
            "alert_activity_available": metrics["alert_available"],
            "alert_activity_status": "available" if metrics["alert_available"] else "unavailable",
            "note": "Converted offline from existing CSV and Markdown health reports.",
        },
        "inventory": rows,
        "metrics": metrics,
        "duplicate_candidates": metrics["duplicate_candidates"],
    }


def load_snapshot(path):
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise DashboardError(f"Health snapshot was not found: {path}") from error
    except json.JSONDecodeError as error:
        raise DashboardError(f"Health snapshot is not valid JSON: {error.msg}") from error
    if not isinstance(snapshot, dict):
        raise DashboardError("Health snapshot root must be a JSON object")
    if snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise DashboardError("Health snapshot has an unsupported schema version")
    snapshot["generated_at"] = utc_timestamp(snapshot.get("generated_at"))
    if not isinstance(snapshot.get("lookback"), str) or not snapshot["lookback"].strip():
        raise DashboardError("Health snapshot must contain a reporting lookback")
    if not isinstance(snapshot.get("collection"), dict):
        raise DashboardError("Health snapshot must contain collection metadata")
    inventory = snapshot.get("inventory")
    if not isinstance(inventory, list):
        raise DashboardError("Health snapshot must contain an inventory list")
    for position, row in enumerate(inventory, start=1):
        if not isinstance(row, dict):
            raise DashboardError(f"Health snapshot inventory item {position} must be an object")
        for field in ("name", "rule_id", "uuid", "enabled", "status", "type", "interval"):
            if field not in row:
                raise DashboardError(f"Health snapshot inventory item {position} is missing {field}")
    return snapshot


def technique_ids(rule):
    values = []
    for threat in rule.get("threat", []):
        if not isinstance(threat, dict):
            continue
        for technique in threat.get("technique", []):
            if not isinstance(technique, dict):
                continue
            if isinstance(technique.get("id"), str):
                values.append(technique["id"])
            for subtechnique in technique.get("subtechnique", []):
                if isinstance(subtechnique, dict) and isinstance(subtechnique.get("id"), str):
                    values.append(subtechnique["id"])
    return values


def load_manifest_coverage(manifest_path):
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    detections = manifest.get("detections") if isinstance(manifest, dict) else None
    if not isinstance(detections, list):
        return set()
    return {
        entry.get("rule_file")
        for entry in detections
        if isinstance(entry, dict) and isinstance(entry.get("rule_file"), str)
    }


def load_repository_rules(detections_directory, manifest_path=None):
    if not detections_directory.is_dir():
        raise DashboardError(f"Detections directory was not found: {detections_directory}")
    covered = load_manifest_coverage(manifest_path) if manifest_path else set()
    repository_rules = []
    stable_id_counts = Counter()
    for path in sorted(detections_directory.glob("*.toml")):
        try:
            with path.open("rb") as file:
                document = tomllib.load(file)
        except tomllib.TOMLDecodeError as error:
            raise DashboardError(f"Malformed detection TOML {path.name}: {error}") from error
        rule = document.get("rule")
        if not isinstance(rule, dict):
            raise DashboardError(f"Detection TOML {path.name} is missing [rule]")
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise DashboardError(f"Detection TOML {path.name} has no usable rule_id")
        stable_id_counts[rule_id] += 1
        rule_file = f"detections/{path.name}"
        repository_rules.append(
            {
                "file": rule_file,
                "rule_id": rule_id,
                "name": rule.get("name", path.stem),
                "description": rule.get("description", ""),
                "severity": rule.get("severity", "Unknown"),
                "risk_score": rule.get("risk_score"),
                "type": rule.get("type", "Unknown"),
                "index": rule.get("index", []),
                "techniques": technique_ids(rule),
                "validation_health": {
                    "manifest_coverage": "Registered" if rule_file in covered else "Not registered",
                    "offline_fixture_tests": "Not assessed",
                    "note": "Fixture matcher execution results are not retained in the health snapshot.",
                },
            }
        )
    if not repository_rules:
        raise DashboardError("No detection TOML files were found")
    for rule in repository_rules:
        if stable_id_counts[rule["rule_id"]] > 1:
            rule["validation_health"]["stable_rule_id"] = "Duplicate"
            rule["validation_health"]["note"] = (
                "Duplicate repository stable rule_id prevents a safe deployment-health correlation."
            )
        else:
            rule["validation_health"]["stable_rule_id"] = "Unique"
    return repository_rules


def telemetry_display(health_row, deployed):
    """Present optional aggregate telemetry without inferring historical results."""
    telemetry = health_row.get("telemetry") if deployed else None
    if not isinstance(telemetry, dict):
        return {
            "status": "NOT_ASSESSED", "assessed_at": None,
            "freshness_threshold_seconds": None, "patterns": [],
            "note": "Telemetry was not assessed in this snapshot.",
        }
    status = telemetry.get("status")
    if not isinstance(status, str) or status not in (
        "FRESH", "STALE", "MISSING", "UNAVAILABLE", "UNKNOWN", "NOT_ASSESSED"
    ):
        status = "UNKNOWN"
    scalar = lambda value: value if value is None or isinstance(value, (str, int, float, bool)) else None
    pattern_fields = (
        "index_pattern", "status", "assessed_at", "freshness_threshold_seconds",
        "timestamp_field", "last_event_timestamp", "recent_event_count", "reason",
    )
    patterns = telemetry.get("patterns")
    return {
        "status": status,
        "assessed_at": scalar(telemetry.get("assessed_at")),
        "freshness_threshold_seconds": scalar(telemetry.get("freshness_threshold_seconds")),
        "patterns": [
            {key: scalar(pattern[key]) for key in pattern_fields if key in pattern}
            for pattern in patterns if isinstance(pattern, dict)
        ] if isinstance(patterns, list) else [],
        "note": "",
    }


def display_row(health_row, repository_rule=None, extra_flags=None):
    repository_rule = repository_rule or {}
    deployed = health_row is not None
    health_row = health_row or {}
    return {
        "name": repository_rule.get("name", health_row.get("name", "Unnamed rule")),
        "rule_id": repository_rule.get("rule_id", health_row.get("rule_id", "Unknown")),
        "uuid": health_row.get("uuid"),
        "description": repository_rule.get("description", ""),
        "severity": repository_rule.get("severity", "Unknown"),
        "risk_score": repository_rule.get("risk_score"),
        "techniques": repository_rule.get("techniques", []),
        "indexes": repository_rule.get("index", []),
        "type": repository_rule.get("type", health_row.get("type", "Unknown")),
        "deployment": {
            "state": "Deployed" if deployed and repository_rule else ("Elastic-only" if deployed else "Repository-only"),
            "enabled": health_row.get("enabled") if deployed else None,
        },
        "operational_health": {
            "status": health_row.get("status", "Unknown") if deployed else "Unknown",
            "last_execution": health_row.get("execution", {}) if deployed else {},
            "interval": health_row.get("interval") if deployed else None,
        },
        "telemetry_health": telemetry_display(health_row, deployed),
        "alert_activity": {
            "available": deployed and not bool(health_row.get("alert_error")),
            "count": health_row.get("alert_activity", {}).get("count") if health_row.get("alert_activity") else 0 if deployed and not health_row.get("alert_error") else None,
            "last_alert": health_row.get("alert_activity", {}).get("last_alert") if health_row.get("alert_activity") else None,
            "note": health_row.get("alert_error") or ("No recorded alerts in the reporting lookback." if deployed and not health_row.get("alert_activity") else ""),
        },
        "validation_health": repository_rule.get(
            "validation_health",
            {"manifest_coverage": "Not assessed", "offline_fixture_tests": "Not assessed", "note": "Elastic-only rule."},
        ),
        "detection_effectiveness": {
            "status": "Not assessed",
            "note": "True-positive and false-positive metrics require labeled outcome data and are not collected by this dashboard.",
        },
        "review_flags": (
            (health_row.get("review_flags", []) if deployed else ["NOT_DEPLOYED_IN_SNAPSHOT"])
            + list(extra_flags or [])
        ),
    }


def correlate_rules(repository_rules, health_rows):
    repository_by_id = defaultdict(list)
    for rule in repository_rules:
        repository_by_id[rule["rule_id"]].append(rule)
    matched = []
    elastic_only = []
    safely_matched_repository_ids = set()
    for health_row in health_rows:
        candidates = repository_by_id.get(health_row["rule_id"], [])
        if len(candidates) == 1:
            matched.append(display_row(health_row, candidates[0]))
            safely_matched_repository_ids.add(candidates[0]["rule_id"])
        else:
            flags = ["AMBIGUOUS_REPOSITORY_STABLE_ID"] if candidates else []
            elastic_only.append(display_row(health_row, extra_flags=flags))
    repository_only = [
        display_row(
            None,
            rule,
            extra_flags=["DUPLICATE_REPOSITORY_STABLE_ID"]
            if len(repository_by_id[rule["rule_id"]]) > 1
            else [],
        )
        for rule in repository_rules
        if rule["rule_id"] not in safely_matched_repository_ids
    ]
    return {"matched": matched, "repository_only": repository_only, "elastic_only": elastic_only}


def dashboard_model(snapshot, repository_rules):
    correlation = correlate_rules(repository_rules, snapshot["inventory"])
    rows = correlation["matched"] + correlation["repository_only"] + correlation["elastic_only"]
    metrics = snapshot_metrics(snapshot["inventory"])
    review_rows = [row for row in rows if row["review_flags"]]
    status_counts = metrics["status_counts"]
    techniques = sorted({technique for row in rows for technique in row["techniques"]})
    severities = sorted({str(row["severity"]) for row in rows})
    return {
        "snapshot": {
            "generated_at": snapshot["generated_at"],
            "lookback": snapshot["lookback"],
            "source_kind": snapshot["collection"].get("source_kind", "unknown"),
            "is_live": snapshot["collection"].get("is_live") is True,
            "note": snapshot["collection"].get("note", ""),
        },
        "summary": {
            "repository_managed": len(repository_rules),
            "deployed_rules": metrics["total"],
            "enabled": metrics["enabled"],
            "disabled": metrics["disabled"],
            "statuses": {status: status_counts.get(status, 0) for status in ("HEALTHY", "FAILED", "DEGRADED", "STALE", "UNKNOWN", "NOT_YET_EXECUTED")},
            "review_count": len(review_rows),
            "total_alerts": metrics["total_alerts"],
            "alert_available": metrics["alert_available"],
        },
        "rows": rows,
        "review_sections": {
            "zero_alerts": [row for row in rows if "ZERO_ALERTS_IN_LOOKBACK" in row["review_flags"]],
            "execution_concerns": [row for row in rows if row["operational_health"]["status"] in {"FAILED", "DEGRADED", "STALE"}],
            "telemetry_concerns": [
                row for row in rows
                if row["telemetry_health"]["status"] in {"STALE", "MISSING", "UNAVAILABLE", "UNKNOWN"}
            ],
            "duplicate_candidates": [
                [row for row in rows if row["uuid"] in group]
                for group in snapshot_metrics(snapshot["inventory"])["duplicate_candidates"]
            ],
            "insufficient_data": [
                row
                for row in rows
                if row["operational_health"]["status"] in {"UNKNOWN", "NOT_YET_EXECUTED"}
                or not row["alert_activity"]["available"]
            ],
        },
        "filters": {"statuses": sorted({row["operational_health"]["status"] for row in rows}), "severities": severities, "techniques": techniques},
        "limitations": [
            "Operational execution health does not prove detection coverage or effectiveness.",
            "Telemetry freshness is a configurable ingestion-availability heuristic and does not prove detection effectiveness.",
            "Zero alerts are a review opportunity, not a failure classification.",
            "Fixture matcher status is not a real Elastic KQL execution result.",
            "True-positive and false-positive metrics are not assessed without labeled outcome data.",
        ],
    }


def safe_json_for_html(value):
    """Prevent JSON embedded in a script element from terminating that element."""
    return json.dumps(value, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def dashboard_html(model):
    embedded = safe_json_for_html(model)
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Detection Health Dashboard</title>
  <link rel=\"stylesheet\" href=\"{DASHBOARD_CSS}\">
</head>
<body>
  <main class=\"shell\">
    <header class=\"hero\">
      <p class=\"eyebrow\">Detection Engineering Lab</p>
      <h1>Detection Health Dashboard</h1>
      <p class=\"subtitle\">Operational health, telemetry freshness, deployment state, alert activity, and available validation evidence.</p>
      <div id=\"snapshot-status\" class=\"snapshot-status\" aria-live=\"polite\"></div>
    </header>
    <section id=\"summary-cards\" class=\"summary-grid\" aria-label=\"Dashboard summary\"></section>
    <section class=\"panel\">
      <div class=\"section-heading\"><div><p class=\"eyebrow\">Inventory</p><h2>Detection coverage and health</h2></div><p id=\"inventory-count\" class=\"muted\"></p></div>
      <div class=\"controls\"><label>Search<input id=\"search\" type=\"search\" placeholder=\"Name, stable ID, or UUID\"></label><label>Health<select id=\"health-filter\"></select></label><label>Severity<select id=\"severity-filter\"></select></label><label>ATT&amp;CK technique<select id=\"technique-filter\"></select></label></div>
      <div class=\"table-wrap\"><table><thead><tr><th data-sort=\"name\">Detection</th><th data-sort=\"rule_id\">Stable ID</th><th>ATT&amp;CK</th><th data-sort=\"severity\">Severity</th><th data-sort=\"type\">Type</th><th>Deployment</th><th data-sort=\"status\">Operational health</th><th>Telemetry</th><th>Last execution</th><th data-sort=\"alert_count\">Alerts</th><th>Review</th></tr></thead><tbody id=\"inventory-body\"></tbody></table></div>
    </section>
    <section class=\"details-layout\"><aside class=\"panel\"><p class=\"eyebrow\">Rule detail</p><div id=\"rule-detail\" class=\"detail-empty\">Select a detection to inspect its independent health dimensions.</div></aside><aside class=\"panel\"><p class=\"eyebrow\">Review queue</p><div id=\"review-sections\"></div></aside></section>
    <section class=\"panel\"><p class=\"eyebrow\">Interpretation</p><h2>What this dashboard does not claim</h2><ul id=\"limitations\" class=\"limitations\"></ul></section>
  </main>
  <script id=\"dashboard-data\" type=\"application/json\">{embedded}</script>
  <script src=\"{DASHBOARD_JS}\"></script>
</body>
</html>
"""


DASHBOARD_CSS_CONTENT = """
:root { --bg:#07111f; --panel:#0e1b2e; --panel-2:#12243c; --line:#274464; --text:#e7f0fb; --muted:#9bb1ca; --blue:#5aa9ff; --green:#54d3a5; --yellow:#f5c96a; --red:#ff7d87; --purple:#b496ff; }
* { box-sizing:border-box; }
body { margin:0; background:radial-gradient(circle at top right,#102b4d 0,transparent 34rem),var(--bg); color:var(--text); font-family:Inter,Segoe UI,Arial,sans-serif; line-height:1.45; }
.shell { max-width:1540px; margin:auto; padding:36px 24px 56px; }
.hero { margin-bottom:24px; }.hero h1 { margin:2px 0 8px; font-size:clamp(2rem,4vw,3.6rem); letter-spacing:-.045em; }.subtitle,.muted { color:var(--muted); }.eyebrow { margin:0 0 5px; color:var(--blue); font-size:.75rem; font-weight:800; letter-spacing:.12em; text-transform:uppercase; }
.snapshot-status { margin-top:16px; padding:12px 14px; border:1px solid var(--yellow); background:#2d2511; color:#ffe5a9; border-radius:10px; font-weight:650; }
.summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(165px,1fr)); gap:12px; margin:22px 0; }.card,.panel { border:1px solid var(--line); background:linear-gradient(145deg,rgba(18,36,60,.98),rgba(10,23,40,.98)); border-radius:14px; box-shadow:0 12px 34px rgba(0,0,0,.18); }.card { padding:16px; min-height:112px; }.card-label { color:var(--muted); font-size:.85rem; }.card-value { margin-top:8px; font-size:1.75rem; font-weight:800; }.panel { padding:20px; margin-top:18px; }.section-heading { display:flex; align-items:end; justify-content:space-between; gap:16px; }.section-heading h2,.panel h2 { margin:0; font-size:1.3rem; }
.controls { display:grid; grid-template-columns:2fr repeat(3,minmax(130px,1fr)); gap:12px; margin:20px 0; }.controls label { color:var(--muted); font-size:.8rem; font-weight:700; }.controls input,.controls select { display:block; width:100%; margin-top:6px; border:1px solid var(--line); border-radius:8px; padding:10px; color:var(--text); background:#091728; }
.table-wrap { overflow:auto; } table { width:100%; min-width:1120px; border-collapse:collapse; font-size:.87rem; } th,td { padding:12px 10px; text-align:left; border-bottom:1px solid rgba(39,68,100,.65); vertical-align:top; } th { color:var(--muted); cursor:pointer; white-space:nowrap; font-size:.73rem; letter-spacing:.04em; text-transform:uppercase; } tr[data-rule] { cursor:pointer; } tr[data-rule]:hover { background:rgba(90,169,255,.08); }.rule-name { font-weight:750; }.small { color:var(--muted); font-size:.77rem; overflow-wrap:anywhere; }.badge { display:inline-block; padding:3px 7px; border-radius:999px; font-size:.72rem; font-weight:800; white-space:nowrap; }.HEALTHY,.Deployed,.enabled { color:#bff5df; background:#123d35; }.FAILED,.DEGRADED,.STALE,.DISABLED,.disabled { color:#ffd0d3; background:#4a1c25; }.UNKNOWN,.NOT_YET_EXECUTED,.Repository-only,.Elastic-only { color:#ffe5a9; background:#4a3918; }.flag { margin:2px 2px 2px 0; background:#243c5a; color:#c8dfff; }.details-layout { display:grid; grid-template-columns:1.1fr .9fr; gap:18px; }.details-layout .panel { margin-top:18px; }.detail-grid { display:grid; grid-template-columns:150px 1fr; gap:8px 14px; margin-top:12px; }.detail-grid dt { color:var(--muted); font-weight:700; }.detail-grid dd { margin:0; overflow-wrap:anywhere; }.review-group { margin:15px 0; }.review-group h3 { margin:0 0 6px; font-size:.96rem; }.review-group ul,.limitations { margin:0; padding-left:19px; }.review-group li,.limitations li { margin:6px 0; color:var(--muted); }.detail-empty { color:var(--muted); padding:20px 0; } @media (max-width:850px) { .shell { padding:22px 14px; }.controls,.details-layout { grid-template-columns:1fr; }.section-heading { align-items:start; flex-direction:column; }.detail-grid { grid-template-columns:1fr; gap:2px; }.detail-grid dd { margin-bottom:10px; } }
""".strip() + "\n"


DASHBOARD_JS_CONTENT = r"""
(() => {
  const dataElement = document.getElementById("dashboard-data");
  const model = JSON.parse(dataElement.textContent);
  const state = { query: "", health: "", severity: "", technique: "", sort: "name", direction: 1 };
  const byId = (id) => document.getElementById(id);
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };
  const element = (tag, className = "") => { const node = document.createElement(tag); if (className) node.className = className; return node; };
  const text = (node, value) => { node.textContent = value === null || value === undefined || value === "" ? "N/A" : String(value); return node; };
  const statusClass = (value) => String(value || "UNKNOWN").replaceAll(" ", "_");
  const ageText = (timestamp) => { const age = Math.max(0, Date.now() - Date.parse(timestamp)); const minutes = Math.floor(age / 60000); if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`; const hours = Math.floor(minutes / 60); if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"}`; const days = Math.floor(hours / 24); return `${days} day${days === 1 ? "" : "s"}`; };
  const badge = (value) => { const node = element("span", `badge ${statusClass(value)}`); return text(node, value); };
  const field = (label, value, target) => { const dt = element("dt"); text(dt, label); const dd = element("dd"); if (value instanceof Node) dd.appendChild(value); else text(dd, value); target.append(dt, dd); };
  const addOptions = (id, values) => { const select = byId(id); const any = element("option"); any.value = ""; any.textContent = "All"; select.appendChild(any); values.forEach((value) => { const option = element("option"); option.value = value; option.textContent = value; select.appendChild(option); }); };
  const formatAlert = (row) => !row.alert_activity.available ? "N/A" : row.alert_activity.count === 0 ? "0" : String(row.alert_activity.count);
  const renderSummary = () => {
    const cards = [
      ["Repository-managed", model.summary.repository_managed], ["Deployed Elastic rules", model.summary.deployed_rules], ["Enabled / disabled", `${model.summary.enabled} / ${model.summary.disabled}`], ["Healthy", model.summary.statuses.HEALTHY], ["Execution concerns", model.summary.statuses.FAILED + model.summary.statuses.DEGRADED + model.summary.statuses.STALE], ["Requires review", model.summary.review_count], ["Alerts in lookback", model.summary.alert_available ? model.summary.total_alerts : "N/A"]
    ];
    const parent = byId("summary-cards"); clear(parent); cards.forEach(([label, value]) => { const card = element("article", "card"); const title = element("div", "card-label"); text(title, label); const amount = element("div", "card-value"); text(amount, value); card.append(title, amount); parent.appendChild(card); });
  };
  const filteredRows = () => model.rows.filter((row) => {
    const haystack = [row.name, row.rule_id, row.uuid, ...(row.techniques || [])].join(" ").toLowerCase();
    return (!state.query || haystack.includes(state.query)) && (!state.health || row.operational_health.status === state.health) && (!state.severity || row.severity === state.severity) && (!state.technique || row.techniques.includes(state.technique));
  }).sort((left, right) => {
    const value = (row) => ({ name: row.name, rule_id: row.rule_id, severity: row.severity, type: row.type, status: row.operational_health.status, alert_count: row.alert_activity.count ?? -1 })[state.sort] ?? "";
    return String(value(left)).localeCompare(String(value(right)), undefined, { numeric: true }) * state.direction;
  });
  const renderRows = () => {
    const rows = filteredRows(); const body = byId("inventory-body"); clear(body); text(byId("inventory-count"), `${rows.length} of ${model.rows.length} detections`);
    rows.forEach((row) => { const tr = element("tr"); tr.dataset.rule = row.uuid || row.rule_id; const values = [
      [row.name, row.uuid || "No deployed UUID"], [row.rule_id], [row.techniques.length ? row.techniques.join(", ") : "N/A"], [row.severity], [row.type], [row.deployment.state + (row.deployment.enabled === null ? "" : row.deployment.enabled ? " · enabled" : " · disabled")], [row.operational_health.status], [row.telemetry_health.status], [row.operational_health.last_execution.date || "N/A"], [formatAlert(row)], [row.review_flags.length ? row.review_flags.join(", ") : "None"]
    ];
      values.forEach((parts, index) => { const td = element("td"); if (index === 0) { const name = element("div", "rule-name"); text(name, parts[0]); const sub = element("div", "small"); text(sub, parts[1]); td.append(name, sub); } else if (index === 5 || index === 6 || index === 7) { td.appendChild(badge(parts[0])); } else if (index === 10 && row.review_flags.length) { row.review_flags.forEach((flag) => { const marker = badge(flag); marker.classList.add("flag"); td.appendChild(marker); }); } else { text(td, parts[0]); } tr.appendChild(td); });
      tr.addEventListener("click", () => renderDetail(row)); body.appendChild(tr);
    });
  };
  const renderDetail = (row) => { const target = byId("rule-detail"); clear(target); target.className = ""; const title = element("h2"); text(title, row.name); const grid = element("dl", "detail-grid"); field("Stable rule ID", row.rule_id, grid); field("Elastic UUID", row.uuid, grid); field("Deployment", row.deployment.state, grid); field("Enabled", row.deployment.enabled === null ? "N/A" : row.deployment.enabled ? "Enabled" : "Disabled", grid); field("Operational health", row.operational_health.status, grid); field("Last execution", row.operational_health.last_execution.date, grid);
    field("Telemetry status", row.telemetry_health.status, grid);
    field("Telemetry assessment time", row.telemetry_health.assessed_at, grid);
    field("Telemetry threshold seconds", row.telemetry_health.freshness_threshold_seconds, grid);
    const patterns = element("ul", "limitations");
    row.telemetry_health.patterns.forEach((pattern) => { const line = element("li");
      text(line, `${pattern.index_pattern ?? "N/A"}: ${pattern.status ?? "UNKNOWN"}; selected field: ${pattern.timestamp_field ?? "N/A"}; latest timestamp: ${pattern.last_event_timestamp ?? "N/A"}; recent count: ${pattern.recent_event_count ?? "N/A"}`);
      patterns.appendChild(line);
    });
    field("Telemetry patterns", row.telemetry_health.patterns.length ? patterns : row.telemetry_health.note || "No per-pattern assessment available.", grid);
    field("Alert activity", formatAlert(row), grid); field("Last alert", row.alert_activity.last_alert, grid); field("MITRE ATT&CK", row.techniques.join(", ") || "N/A", grid); field("Validation", `${row.validation_health.manifest_coverage}; fixture results: ${row.validation_health.offline_fixture_tests}`, grid); field("Effectiveness", `${row.detection_effectiveness.status}: ${row.detection_effectiveness.note}`, grid); field("Review flags", row.review_flags.join(", ") || "None", grid); target.append(title, grid); };
  const reviewList = (title, items, formatter) => { const wrap = element("section", "review-group"); const heading = element("h3"); text(heading, title); const list = element("ul"); if (!items.length) { const item = element("li"); text(item, "None"); list.appendChild(item); } else { items.forEach((item) => { const line = element("li"); text(line, formatter(item)); list.appendChild(line); }); } wrap.append(heading, list); return wrap; };
  const renderReviews = () => { const target = byId("review-sections"); clear(target); target.append(
    reviewList("Zero alerts in lookback", model.review_sections.zero_alerts, (row) => `${row.name} (${row.rule_id})`),
    reviewList("Failed, degraded, or stale", model.review_sections.execution_concerns, (row) => `${row.name}: ${row.operational_health.status}`),
    reviewList("Potential duplicate names", model.review_sections.duplicate_candidates, (group) => group.map((row) => `${row.name} [${row.uuid}]`).join("; ")),
    reviewList("Insufficient health data", model.review_sections.insufficient_data, (row) => `${row.name}: ${row.operational_health.status}`),
    reviewList("Telemetry freshness concerns", model.review_sections.telemetry_concerns, (row) => `${row.name}: ${row.telemetry_health.status}`)
  ); };
  const renderLimitations = () => { const list = byId("limitations"); clear(list); model.limitations.forEach((item) => { const li = element("li"); text(li, item); list.appendChild(li); }); };
  const bind = () => { byId("search").addEventListener("input", (event) => { state.query = event.target.value.toLowerCase().trim(); renderRows(); }); [["health-filter", "health"], ["severity-filter", "severity"], ["technique-filter", "technique"]].forEach(([id, key]) => byId(id).addEventListener("change", (event) => { state[key] = event.target.value; renderRows(); })); document.querySelectorAll("th[data-sort]").forEach((header) => header.addEventListener("click", () => { const next = header.dataset.sort; state.direction = state.sort === next ? -state.direction : 1; state.sort = next; renderRows(); })); };
  const status = byId("snapshot-status"); text(status, `${model.snapshot.is_live ? "Live" : "Historical"} snapshot generated ${model.snapshot.generated_at} · age ${ageText(model.snapshot.generated_at)} · ${model.snapshot.note || "No live browser connection."}`);
  addOptions("health-filter", model.filters.statuses); addOptions("severity-filter", model.filters.severities); addOptions("technique-filter", model.filters.techniques); renderSummary(); renderRows(); renderReviews(); renderLimitations(); bind();
})();
""".strip() + "\n"


def write_bundle(contents, output_directory):
    """Replace generated files together, restoring prior complete files on failure."""
    output_directory.mkdir(parents=True, exist_ok=True)
    targets = {name: output_directory / name for name in contents}
    originals = {target: target.read_bytes() if target.exists() else None for target in targets.values()}
    temporary_paths = {}
    replaced = []
    try:
        for name, content in contents.items():
            target = targets[name]
            temporary = target.with_name(f".{target.name}.tmp")
            temporary.write_text(content, encoding="utf-8", newline="")
            temporary_paths[target] = temporary
        for target in targets.values():
            temporary_paths[target].replace(target)
            replaced.append(target)
    except OSError as error:
        for target in replaced:
            original = originals[target]
            if original is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(original)
        raise DashboardError(f"Dashboard files could not be written safely: {error}") from error
    finally:
        for temporary in temporary_paths.values():
            temporary.unlink(missing_ok=True)
    return targets


def generate_dashboard(model, output_directory):
    return write_bundle(
        {
            DASHBOARD_HTML: dashboard_html(model),
            DASHBOARD_CSS: DASHBOARD_CSS_CONTENT,
            DASHBOARD_JS: DASHBOARD_JS_CONTENT,
        },
        output_directory,
    )


def generate_pages_site(model, output_directory):
    """Build the intentionally small, public GitHub Pages site bundle.

    The browser bundle contains only the already-sanitized dashboard model.  It
    deliberately excludes the raw snapshot and every local report artifact.
    """
    return write_bundle(
        {
            PAGES_INDEX: dashboard_html(model),
            DASHBOARD_CSS: DASHBOARD_CSS_CONTENT,
            DASHBOARD_JS: DASHBOARD_JS_CONTENT,
        },
        output_directory,
    )


def validate_pages_site(output_directory):
    """Reject an incomplete or potentially sensitive Pages artifact bundle."""
    output_directory = Path(output_directory)
    if not output_directory.is_dir():
        raise DashboardError(f"Pages site directory does not exist: {output_directory}")

    actual_files = {path.name for path in output_directory.iterdir() if path.is_file()}
    missing = PUBLISHED_SITE_FILENAMES - actual_files
    unexpected = actual_files - PUBLISHED_SITE_FILENAMES
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing: {', '.join(sorted(missing))}")
        if unexpected:
            details.append(f"unexpected: {', '.join(sorted(unexpected))}")
        raise DashboardError("Pages site files are not safe to publish (" + "; ".join(details) + ")")

    for name in sorted(PUBLISHED_SITE_FILENAMES):
        content = (output_directory / name).read_text(encoding="utf-8").casefold()
        for marker in FORBIDDEN_PUBLISHED_MARKERS:
            if marker in content:
                raise DashboardError(f"Pages site contains a forbidden configuration marker in {name}: {marker}")


def build_from_arguments(arguments):
    reports_directory = Path(arguments.reports_directory)
    if arguments.snapshot:
        snapshot = load_snapshot(Path(arguments.snapshot))
    else:
        snapshot = convert_legacy_reports(
            reports_directory / "detection_health_inventory.csv",
            reports_directory / "detection_health_summary.md",
        )
        write_bundle(
            {SNAPSHOT_FILENAME: json.dumps(snapshot, indent=2, sort_keys=True) + "\n"},
            reports_directory,
        )
    repository_rules = load_repository_rules(
        Path(arguments.detections_directory),
        Path(arguments.manifest),
    )
    model = dashboard_model(snapshot, repository_rules)
    targets = generate_dashboard(model, reports_directory)
    if arguments.site_directory:
        site_targets = generate_pages_site(model, Path(arguments.site_directory))
        validate_pages_site(Path(arguments.site_directory))
        targets.update({f"site_{name}": path for name, path in site_targets.items()})
    return snapshot, model, targets


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description="Build a static Detection Health Dashboard without Elastic access.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--snapshot", help="Path to an existing structured health JSON snapshot.")
    source.add_argument("--from-legacy-reports", action="store_true", help="Convert existing CSV/Markdown reports (default).")
    parser.add_argument("--reports-directory", default=DEFAULT_REPORTS_DIRECTORY)
    parser.add_argument(
        "--site-directory",
        help="Optional public static-site directory. Only index.html, CSS, and JavaScript are written.",
    )
    parser.add_argument("--detections-directory", default=DEFAULT_DETECTIONS_DIRECTORY)
    parser.add_argument("--manifest", default=REPOSITORY_ROOT / "tests" / "test_manifest.json")
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse_arguments(argv)
    try:
        snapshot, model, targets = build_from_arguments(arguments)
    except DashboardError as error:
        print(f"ERROR: {error}")
        return 1
    print(
        f"Built {'live' if model['snapshot']['is_live'] else 'historical'} dashboard from "
        f"{snapshot['generated_at']} with {model['summary']['deployed_rules']} deployed rules."
    )
    for path in targets.values():
        print(f"Wrote: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
