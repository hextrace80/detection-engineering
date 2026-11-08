"""Read-only operational health reporting for Elastic Security detections."""

import csv
import io
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import requests


RULES_PAGE_SIZE = 100
ALERT_BUCKET_PAGE_SIZE = 500
MAX_ALERT_BUCKET_PAGES = 10000
DEFAULT_LOOKBACK = "now-30d"
DEFAULT_STALE_AFTER_SECONDS = 900
DEFAULT_STALE_INTERVAL_MULTIPLIER = 3
DEFAULT_TELEMETRY_FRESHNESS_SECONDS = 86400
SAFE_INDEX_PATTERN_RE = re.compile(r"^[a-z0-9._*?-]+$")
TELEMETRY_STATUS_PRECEDENCE = ("UNAVAILABLE", "MISSING", "STALE", "UNKNOWN")
REPORTS_DIRECTORY = Path(__file__).resolve().parents[1] / "reports"
INVENTORY_REPORT_NAME = "detection_health_inventory.csv"
SUMMARY_REPORT_NAME = "detection_health_summary.md"
SNAPSHOT_REPORT_NAME = "detection_health_snapshot.json"
SNAPSHOT_SCHEMA_VERSION = 1


class HealthMonitorError(Exception):
    """Raised when read-only health data cannot be retrieved safely."""


def api_headers(api_key):
    return {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {api_key}",
    }


def response_json(response, context):
    try:
        document = response.json()
    except ValueError as error:
        raise HealthMonitorError(f"{context}: Elastic returned a non-JSON response") from error
    if not isinstance(document, dict):
        raise HealthMonitorError(f"{context}: Elastic returned an unexpected JSON response")
    return document


def response_detail(response):
    text = response.text.strip()
    return text[:500] if text else "no response body"


def kibana_rules_url(kibana_url, space):
    return f"{kibana_url.rstrip('/')}/s/{quote(space, safe='')}/api/detection_engine/rules/_find"


def alert_index_url(elasticsearch_url, space):
    return f"{elasticsearch_url.rstrip('/')}/.alerts-security.alerts-{quote(space, safe='')}/_search"


def telemetry_freshness_seconds(environment=os.environ):
    raw = environment.get("ELASTIC_TELEMETRY_FRESHNESS_SECONDS", str(DEFAULT_TELEMETRY_FRESHNESS_SECONDS))
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise HealthMonitorError("ELASTIC_TELEMETRY_FRESHNESS_SECONDS must be a positive integer") from error
    if value <= 0:
        raise HealthMonitorError("ELASTIC_TELEMETRY_FRESHNESS_SECONDS must be a positive integer")
    telemetry_window_start(datetime.now(timezone.utc), value)
    return value


def telemetry_window_start(assessed_at, threshold_seconds):
    try:
        return assessed_at.astimezone(timezone.utc) - timedelta(seconds=threshold_seconds)
    except (OverflowError, ValueError) as error:
        raise HealthMonitorError(
            "ELASTIC_TELEMETRY_FRESHNESS_SECONDS must define a representable UTC assessment window"
        ) from error


def normalize_index_pattern(value):
    if not isinstance(value, str):
        return None
    pattern = value.strip().casefold()
    if not pattern or pattern in {"*", "_all"} or not SAFE_INDEX_PATTERN_RE.fullmatch(pattern):
        return None
    return pattern


def telemetry_resolve_url(elasticsearch_url, pattern):
    return f"{elasticsearch_url.rstrip('/')}/_resolve/index/{quote(pattern, safe='*._-')}"


def telemetry_search_url(elasticsearch_url, pattern):
    return f"{elasticsearch_url.rstrip('/')}/{quote(pattern, safe='*._-')}/_search"


def telemetry_aggregation_body(window_start):
    window_text = generation_timestamp(window_start)
    return {
        "size": 0,
        "track_total_hits": False,
        "aggs": {
            "latest_ingested": {"max": {"field": "event.ingested", "format": "strict_date_optional_time"}},
            "latest_timestamp": {"max": {"field": "@timestamp", "format": "strict_date_optional_time"}},
            "recent_ingested": {"filter": {"range": {"event.ingested": {"gte": window_text}}}},
            "recent_timestamp": {"filter": {"range": {"@timestamp": {"gte": window_text}}}},
        },
    }


def assess_index_pattern(session, elasticsearch_url, headers, pattern, assessed_at, threshold_seconds):
    """Assess one source using metadata and aggregates, publishing no response details."""
    pattern = normalize_index_pattern(pattern)
    assessment = {
        "index_pattern": pattern,
        "status": "UNAVAILABLE",
        "assessed_at": generation_timestamp(assessed_at),
        "freshness_threshold_seconds": threshold_seconds,
        "timestamp_field": None,
        "last_event_timestamp": None,
        "recent_event_count": None,
    }

    def result(status, reason):
        return dict(assessment, status=status, reason=reason)

    if pattern is None:
        return result("NOT_ASSESSED", "UNSUPPORTED_INDEX_PATTERN")

    window_start = telemetry_window_start(assessed_at, threshold_seconds)
    try:
        response = session.get(
            telemetry_resolve_url(elasticsearch_url, pattern),
            params={"expand_wildcards": "open", "allow_no_indices": "true", "ignore_unavailable": "true"},
            headers=headers,
            timeout=30,
        )
    except requests.Timeout:
        return result("UNAVAILABLE", "RESOLVE_TIMEOUT")
    except requests.RequestException:
        return result("UNAVAILABLE", "RESOLVE_REQUEST_FAILED")

    if response.status_code == 403:
        return result("UNAVAILABLE", "RESOLVE_HTTP_403")
    try:
        document = response_json(response, "Telemetry resolution")
    except HealthMonitorError:
        return result("UNAVAILABLE", "RESOLVE_INVALID_RESPONSE")
    if response.status_code != 200:
        error = document.get("error")
        if isinstance(error, dict) and error.get("type") == "index_not_found_exception":
            return result("MISSING", "INDEX_NOT_FOUND")
        return result("UNAVAILABLE", f"RESOLVE_HTTP_{response.status_code}")

    sources = [document.get(kind) for kind in ("indices", "aliases", "data_streams")]
    if any(not isinstance(source, list) for source in sources):
        return result("UNAVAILABLE", "RESOLVE_INVALID_RESPONSE")
    for source in sources:
        if any(not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"].strip() for item in source):
            return result("UNAVAILABLE", "RESOLVE_INVALID_RESPONSE")
    if not any(sources):
        return result("MISSING", "NO_RESOLVED_SOURCE")

    try:
        response = session.post(
            telemetry_search_url(elasticsearch_url, pattern),
            json=telemetry_aggregation_body(window_start),
            headers=headers,
            timeout=30,
        )
    except requests.Timeout:
        return result("UNAVAILABLE", "SEARCH_TIMEOUT")
    except requests.RequestException:
        return result("UNAVAILABLE", "SEARCH_REQUEST_FAILED")
    if response.status_code != 200:
        return result("UNAVAILABLE", f"SEARCH_HTTP_{response.status_code}")
    try:
        document = response_json(response, "Telemetry aggregation")
    except HealthMonitorError:
        return result("UNAVAILABLE", "SEARCH_INVALID_RESPONSE")
    if document.get("timed_out") is not False:
        return result("UNAVAILABLE", "SEARCH_TIMEOUT")
    shards = document.get("_shards")
    if not isinstance(shards, dict) or type(shards.get("failed")) is not int or shards["failed"] < 0:
        return result("UNAVAILABLE", "SEARCH_INVALID_RESPONSE")
    if shards["failed"] > 0:
        return result("UNAVAILABLE", "SEARCH_SHARD_FAILURE")
    aggregations = document.get("aggregations")
    names = ("latest_ingested", "latest_timestamp", "recent_ingested", "recent_timestamp")
    if not isinstance(aggregations, dict) or any(not isinstance(aggregations.get(name), dict) for name in names):
        return result("UNAVAILABLE", "SEARCH_INVALID_RESPONSE")
    for name in ("recent_ingested", "recent_timestamp"):
        count = aggregations[name].get("doc_count")
        if type(count) is not int or count < 0:
            return result("UNAVAILABLE", "SEARCH_INVALID_RESPONSE")

    # Fall back as a pair: the chosen timestamp field always owns the count.
    selected = None
    for suffix, field in (("ingested", "event.ingested"), ("timestamp", "@timestamp")):
        candidate = parse_timestamp(aggregations[f"latest_{suffix}"].get("value_as_string"))
        assessment["timestamp_field"] = field
        assessment["recent_event_count"] = aggregations[f"recent_{suffix}"]["doc_count"]
        if candidate is not None and candidate.tzinfo is not None:
            try:
                selected = candidate.astimezone(timezone.utc)
            except (OverflowError, ValueError):
                continue
            break
    if selected is None:
        return result("UNKNOWN", "NO_VALID_TIMESTAMP")
    assessment["last_event_timestamp"] = generation_timestamp(selected)
    assessment["status"] = "FRESH" if selected >= window_start else "STALE"
    return assessment


def telemetry_rollup(patterns, assessed_at, threshold_seconds):
    assessment = {
        "status": "NOT_ASSESSED",
        "assessed_at": generation_timestamp(assessed_at),
        "freshness_threshold_seconds": threshold_seconds,
        "patterns": patterns,
    }
    for status in TELEMETRY_STATUS_PRECEDENCE:
        if any(pattern["status"] == status for pattern in patterns):
            return dict(assessment, status=status)
    if patterns and all(pattern["status"] == "FRESH" for pattern in patterns):
        return dict(assessment, status="FRESH")
    return assessment


def collect_rule_telemetry(session, elasticsearch_url, headers, rules, assessed_at, threshold_seconds):
    """Resolve and assess each safe source once per run, retaining declared order."""
    cache = {}
    telemetry = {}
    assessed_text = generation_timestamp(assessed_at)
    for rule in rules:
        patterns = []
        declared = rule.get("index")
        for value in declared if isinstance(declared, list) else []:
            pattern = normalize_index_pattern(value)
            key = (pattern, threshold_seconds, assessed_text)
            if key not in cache:
                cache[key] = assess_index_pattern(
                    session, elasticsearch_url, headers, pattern, assessed_at, threshold_seconds
                )
            patterns.append(dict(cache[key]))
        telemetry[rule["id"]] = telemetry_rollup(patterns, assessed_at, threshold_seconds)
    return telemetry


def get_rules(session, kibana_url, space, headers):
    rules = []
    page = 1
    total = None
    url = kibana_rules_url(kibana_url, space)

    while total is None or len(rules) < total:
        try:
            response = session.get(
                url,
                params={"page": page, "per_page": RULES_PAGE_SIZE},
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as error:
            raise HealthMonitorError(f"List rules request failed: {error}") from error

        if response.status_code != 200:
            raise HealthMonitorError(
                f"List rules failed with HTTP {response.status_code}: {response_detail(response)}"
            )

        document = response_json(response, f"List rules page {page}")
        page_rules = document.get("data")
        page_total = document.get("total")
        if not isinstance(page_rules, list) or not isinstance(page_total, int) or page_total < 0:
            raise HealthMonitorError(f"List rules page {page}: missing valid data or total")
        if total is None:
            total = page_total
        elif total != page_total:
            raise HealthMonitorError("List rules returned an inconsistent total while paging")
        if total > len(rules) and not page_rules:
            raise HealthMonitorError("List rules ended before all expected rules were returned")

        for position, rule in enumerate(page_rules, start=len(rules) + 1):
            if not isinstance(rule, dict):
                raise HealthMonitorError(f"List rules page {page}: rule {position} is not an object")
            rule_uuid = rule.get("id")
            if not isinstance(rule_uuid, str) or not rule_uuid.strip():
                raise HealthMonitorError(f"List rules page {page}: rule {position} has no usable id")

        rules.extend(page_rules)
        page += 1

    return rules


def alert_aggregation_body(lookback, after_key=None):
    composite = {
        "size": ALERT_BUCKET_PAGE_SIZE,
        "sources": [{"rule_uuid": {"terms": {"field": "kibana.alert.rule.uuid"}}}],
    }
    if after_key is not None:
        composite["after"] = after_key

    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"range": {"@timestamp": {"gte": lookback}}},
        "aggs": {
            "rules": {
                "composite": composite,
                "aggs": {"last_alert": {"max": {"field": "@timestamp"}}},
            }
        },
    }


def get_alert_activity(session, elasticsearch_url, space, headers, lookback):
    activity = {}
    after_key = None
    page_count = 0
    url = alert_index_url(elasticsearch_url, space)

    while True:
        page_count += 1
        if page_count > MAX_ALERT_BUCKET_PAGES:
            raise HealthMonitorError("Alert aggregation exceeded the configured page safety limit")
        try:
            response = session.post(
                url,
                json=alert_aggregation_body(lookback, after_key),
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as error:
            raise HealthMonitorError(f"Alert aggregation request failed: {error}") from error

        if response.status_code != 200:
            raise HealthMonitorError(
                f"Alert aggregation failed with HTTP {response.status_code}: {response_detail(response)}"
            )

        document = response_json(response, f"Alert aggregation page {page_count}")
        timed_out = document.get("timed_out")
        if timed_out is True:
            raise HealthMonitorError(f"Alert aggregation page {page_count}: search timed out")
        if timed_out is not None and not isinstance(timed_out, bool):
            raise HealthMonitorError(f"Alert aggregation page {page_count}: invalid timed_out value")

        shards = document.get("_shards")
        if shards is not None:
            if not isinstance(shards, dict) or not isinstance(shards.get("failed", 0), int):
                raise HealthMonitorError(f"Alert aggregation page {page_count}: invalid shard metadata")
            if shards["failed"] > 0:
                raise HealthMonitorError(f"Alert aggregation page {page_count}: shard failures reported")

        aggregation = document.get("aggregations", {}).get("rules")
        if not isinstance(aggregation, dict) or not isinstance(aggregation.get("buckets"), list):
            raise HealthMonitorError(f"Alert aggregation page {page_count}: missing buckets")

        buckets = aggregation["buckets"]
        for bucket in buckets:
            rule_uuid = bucket.get("key", {}).get("rule_uuid")
            count = bucket.get("doc_count")
            last_alert = bucket.get("last_alert", {}).get("value_as_string")
            if not isinstance(rule_uuid, str) or not isinstance(count, int):
                raise HealthMonitorError(f"Alert aggregation page {page_count}: malformed bucket")
            activity[rule_uuid] = {"count": count, "last_alert": last_alert}

        after_key = aggregation.get("after_key")
        if after_key is None:
            return activity
        if not isinstance(after_key, dict) or not buckets:
            raise HealthMonitorError("Alert aggregation returned an invalid continuation key")


def parse_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_interval_seconds(value):
    if not isinstance(value, str) or len(value) < 2 or not value[:-1].isdigit():
        return None
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(value[-1])
    if multiplier is None:
        return None
    return int(value[:-1]) * multiplier


def last_execution_for_rule(rule):
    """Return a safe execution object when Kibana omits or malforms its summary."""
    execution_summary = rule.get("execution_summary")
    if not isinstance(execution_summary, dict):
        return {}

    last_execution = execution_summary.get("last_execution")
    return last_execution if isinstance(last_execution, dict) else {}


def classify_rule(rule, now, default_stale_after, interval_multiplier):
    if rule.get("enabled") is False:
        return "DISABLED"

    last_execution = last_execution_for_rule(rule)
    if not last_execution:
        return "NOT_YET_EXECUTED"

    execution_status = last_execution.get("status")
    if execution_status == "failed":
        return "FAILED"
    if execution_status == "partial failure":
        return "DEGRADED"
    if execution_status != "succeeded":
        return "UNKNOWN"

    execution_time = parse_timestamp(last_execution.get("date"))
    if execution_time is None:
        return "UNKNOWN"
    if execution_time.tzinfo is None:
        execution_time = execution_time.replace(tzinfo=timezone.utc)

    interval_seconds = parse_interval_seconds(rule.get("interval"))
    stale_after = max(
        default_stale_after,
        interval_seconds * interval_multiplier if interval_seconds else default_stale_after,
    )
    if (now - execution_time).total_seconds() > stale_after:
        return "STALE"
    return "HEALTHY"


def build_rows(rules, activity, alert_error, now, default_stale_after, interval_multiplier, telemetry_by_rule=None):
    rows = []
    for rule in rules:
        rule_uuid = rule.get("id")
        rule_activity = activity.get(rule_uuid) if activity is not None else None
        row = {
            "name": rule.get("name", "<unnamed rule>"),
            "rule_id": rule.get("rule_id", "<missing rule_id>"),
            "uuid": rule_uuid,
            "enabled": rule.get("enabled") is True,
            "type": rule.get("type", "<unknown type>"),
            "interval": rule.get("interval", "<unknown interval>"),
            "status": classify_rule(rule, now, default_stale_after, interval_multiplier),
            "execution": last_execution_for_rule(rule),
            "alert_activity": rule_activity,
            "alert_error": alert_error,
        }
        row["telemetry"] = (telemetry_by_rule or {}).get(rule_uuid, {
            "status": "NOT_ASSESSED",
            "assessed_at": None,
            "freshness_threshold_seconds": None,
            "patterns": [],
        })
        row["review_flags"] = review_flags(row)
        rows.append(row)
    return rows


def review_flags(row):
    flags = []
    if not row["enabled"]:
        flags.append("DISABLED")
    elif row["status"] != "HEALTHY":
        flags.append(f"EXECUTION_{row['status']}")

    if row["alert_error"]:
        flags.append("ALERT_ACTIVITY_UNAVAILABLE")
    elif row["enabled"] and row["alert_activity"] is None:
        flags.append("ZERO_ALERTS_IN_LOOKBACK")
    telemetry_status = row.get("telemetry", {}).get("status")
    if telemetry_status in TELEMETRY_STATUS_PRECEDENCE:
        flags.append(f"TELEMETRY_{telemetry_status}")
    return flags


def alert_text(row, lookback):
    if row["alert_error"]:
        return "UNAVAILABLE"
    activity = row["alert_activity"]
    if activity is None:
        return f"no alerts in {lookback}"
    return f"{activity['count']} in {lookback}"


def execution_text(execution):
    if not execution:
        return "no execution data"
    status = execution.get("status", "unknown")
    date = execution.get("date", "unknown time")
    return f"{status} @ {date}"


def print_report(rows, lookback, alert_error):
    print(f"Detection health report (alert lookback: {lookback})")
    print(f"{'STATUS':<18} {'ALERT ACTIVITY':<24} {'RULE':<42} LAST EXECUTION")
    for row in rows:
        print(
            f"{row['status']:<18} {alert_text(row, lookback):<24} "
            f"{row['name'][:42]:<42} {execution_text(row['execution'])}"
        )

    counts = Counter(row["status"] for row in rows)
    summary = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
    print(f"Summary: {summary or 'no rules returned'}")
    if alert_error:
        print(f"WARNING: alert activity is unavailable: {alert_error}")


def normalize_rule_name(name):
    return " ".join(name.split()).casefold()


def duplicate_name_candidates(rows):
    candidates = {}
    for row in rows:
        normalized_name = normalize_rule_name(row["name"])
        candidates.setdefault(normalized_name, []).append(row)
    return [group for group in candidates.values() if len(group) > 1]


def alert_fields(row):
    if row["alert_error"]:
        return "UNAVAILABLE", "UNAVAILABLE"
    activity = row["alert_activity"]
    if activity is None:
        return 0, ""
    return activity["count"], activity.get("last_alert") or ""


def generation_timestamp(generated_at):
    return generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def inventory_csv(rows, generated_at):
    fieldnames = [
        "Report generation timestamp",
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
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    generated_text = generation_timestamp(generated_at)
    for row in sorted(rows, key=lambda item: (item["name"].casefold(), item["uuid"])):
        alert_count, last_alert = alert_fields(row)
        execution = row["execution"]
        writer.writerow(
            {
                "Report generation timestamp": generated_text,
                "Rule name": row["name"],
                "Stable rule_id": row["rule_id"],
                "Elastic internal UUID": row["uuid"],
                "Enabled state": "enabled" if row["enabled"] else "disabled",
                "Health classification": row["status"],
                "Rule type": row["type"],
                "Execution interval": row["interval"],
                "Last execution time": execution.get("date", ""),
                "Last execution status": execution.get("status", ""),
                "Alert count for selected lookback": alert_count,
                "Most recent alert timestamp": last_alert,
                "Review flags": "; ".join(row["review_flags"]),
            }
        )
    return output.getvalue()


def summary_metrics(rows):
    status_counts = Counter(row["status"] for row in rows)
    enabled_rows = [row for row in rows if row["enabled"]]
    disabled_rows = [row for row in rows if not row["enabled"]]
    healthy_enabled = sum(row["status"] == "HEALTHY" for row in enabled_rows)
    alert_available = not any(row["alert_error"] for row in rows)
    alerting_enabled = []
    zero_alert_enabled = []
    total_alerts = None
    top_alerts = []
    if alert_available:
        alerting_enabled = [
            row for row in enabled_rows if row["alert_activity"] is not None and row["alert_activity"]["count"] > 0
        ]
        zero_alert_enabled = [row for row in enabled_rows if row["alert_activity"] is None]
        total_alerts = sum(activity["count"] for row in rows if (activity := row["alert_activity"]) is not None)
        top_alerts = sorted(
            (row for row in rows if row["alert_activity"] is not None),
            key=lambda row: (-row["alert_activity"]["count"], row["name"].casefold(), row["uuid"]),
        )[:5]

    return {
        "total": len(rows),
        "enabled": len(enabled_rows),
        "disabled": len(disabled_rows),
        "healthy_enabled": healthy_enabled,
        "status_counts": status_counts,
        "alert_available": alert_available,
        "alerting_enabled": alerting_enabled,
        "zero_alert_enabled": zero_alert_enabled,
        "total_alerts": total_alerts,
        "top_alerts": top_alerts,
        "duplicate_candidates": duplicate_name_candidates(rows),
    }


def markdown_summary(rows, lookback, generated_at):
    metrics = summary_metrics(rows)
    generated_text = generation_timestamp(generated_at)
    lines = [
        "# Detection Health & Metrics Audit Report",
        "",
        f"Generated: {generated_text}",
        f"Alert lookback: `{lookback}`",
        "",
        "## Rule inventory",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Total deployed rules | {metrics['total']} |",
        f"| Enabled | {metrics['enabled']} |",
        f"| Disabled | {metrics['disabled']} |",
    ]
    for status in ("HEALTHY", "FAILED", "DEGRADED", "STALE", "UNKNOWN", "NOT_YET_EXECUTED"):
        lines.append(f"| {status.replace('_', ' ').title()} | {metrics['status_counts'][status]} |")

    denominator = metrics["enabled"]
    rate = (metrics["healthy_enabled"] / denominator * 100) if denominator else 0
    lines.extend(
        [
            "",
            "## Operational health",
            "",
            f"Operational health rate: **{rate:.1f}%** ({metrics['healthy_enabled']} HEALTHY enabled rules / {denominator} enabled rules).",
            "Disabled rules are excluded from this rate.",
            "",
            "## Alert activity",
            "",
        ]
    )
    if metrics["alert_available"]:
        alerting_count = len(metrics["alerting_enabled"])
        alert_rate = (alerting_count / denominator * 100) if denominator else 0
        lines.extend(
            [
                f"Enabled rules with one or more recorded alerts: **{alerting_count} of {denominator} ({alert_rate:.1f}%)**.",
                f"Total alerts in selected lookback: **{metrics['total_alerts']}**.",
                "",
                "### Top five rules by alert volume",
                "",
                "| Rule name | Elastic internal UUID | Alerts | Most recent alert |",
                "| --- | --- | ---: | --- |",
            ]
        )
        if metrics["top_alerts"]:
            for row in metrics["top_alerts"]:
                activity = row["alert_activity"]
                lines.append(f"| {row['name']} | `{row['uuid']}` | {activity['count']} | {activity.get('last_alert') or ''} |")
        else:
            lines.append("| No alert activity in the selected lookback |  | 0 |  |")

        lines.extend(["", "### Enabled rules with zero alerts in the selected lookback", ""])
        if metrics["zero_alert_enabled"]:
            for row in sorted(metrics["zero_alert_enabled"], key=lambda item: (item["name"].casefold(), item["uuid"])):
                lines.append(f"- {row['name']} (`{row['uuid']}`)")
        else:
            lines.append("- None")
    else:
        lines.append("Alert activity: **UNAVAILABLE**. Alert counts and zero-alert analysis were not calculated.")

    lines.extend(["", "## Potential duplicate rules by name", ""])
    if metrics["duplicate_candidates"]:
        for group in metrics["duplicate_candidates"]:
            lines.append(f"- Candidate: **{group[0]['name']}**")
            for row in sorted(group, key=lambda item: item["uuid"]):
                lines.append(f"  - `{row['uuid']}` — stable rule_id: `{row['rule_id']}`")
    else:
        lines.append("- No duplicate-name candidates found.")
    lines.append("These are candidates for investigation, not confirmed duplicates.")

    lines.extend(["", "## Findings and recommended follow-up actions", ""])
    attention = [row for row in rows if row["review_flags"]]
    if attention:
        for row in sorted(attention, key=lambda item: (item["name"].casefold(), item["uuid"])):
            lines.append(f"- Review {row['name']} (`{row['uuid']}`): {', '.join(row['review_flags'])}.")
    else:
        lines.append("- No execution-health, disabled-state, or alert-availability review flags were identified.")
    lines.extend(
        [
            "- Investigate FAILED, DEGRADED, STALE, or UNKNOWN execution states before relying on the affected detection.",
            "- Review disabled rules to confirm they are intentionally inactive.",
            "- Treat zero alerts in the selected lookback as a review prompt for telemetry coverage, rule scope, and expected activity—not proof of a bad rule.",
            "",
            "## Methodology and limitations",
            "",
            "This report lists deployed Elastic Security rules from Kibana and aggregates alert documents by Elastic internal rule UUID over the selected lookback.",
            "A successful execution means the rule most recently ran successfully; it does not prove that the rule searched complete telemetry, matched intended behavior, or detected every relevant event.",
            "Recorded alert activity reflects alerts retained and returned for the selected lookback. Zero alerts do not establish that a rule has never alerted or that it is ineffective.",
            "Telemetry freshness is a configurable ingestion-availability heuristic; investigate telemetry concerns independently of rule execution and alert counts. It does not prove detection effectiveness.",
            "Potential duplicate names are normalized for comparison and remain investigation candidates because distinct rules can intentionally share a name.",
        ]
    )
    return "\n".join(lines) + "\n"


def health_snapshot(rows, lookback, generated_at):
    """Return a credential-free, JSON-serializable health-report snapshot."""
    metrics = summary_metrics(rows)
    alert_available = metrics["alert_available"]
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "generated_at": generation_timestamp(generated_at),
        "lookback": lookback,
        "collection": {
            "source_kind": "live_read_only_collection",
            "is_live": True,
            "alert_activity_available": alert_available,
            "alert_activity_status": "available" if alert_available else "unavailable",
        },
        "inventory": rows,
        "metrics": {
            "total": metrics["total"],
            "enabled": metrics["enabled"],
            "disabled": metrics["disabled"],
            "healthy_enabled": metrics["healthy_enabled"],
            "status_counts": dict(metrics["status_counts"]),
            "alert_available": alert_available,
            "alerting_enabled_count": len(metrics["alerting_enabled"]),
            "zero_alert_enabled_count": len(metrics["zero_alert_enabled"]),
            "total_alerts": metrics["total_alerts"],
        },
        "duplicate_candidates": [
            [row["uuid"] for row in group]
            for group in metrics["duplicate_candidates"]
        ],
    }


def write_audit_reports(rows, lookback, generated_at, reports_directory=REPORTS_DIRECTORY):
    if any(row["alert_error"] for row in rows):
        raise HealthMonitorError("Audit reports were not written because alert activity is unavailable")

    contents = {
        INVENTORY_REPORT_NAME: inventory_csv(rows, generated_at),
        SUMMARY_REPORT_NAME: markdown_summary(rows, lookback, generated_at),
        SNAPSHOT_REPORT_NAME: json.dumps(health_snapshot(rows, lookback, generated_at), indent=2, sort_keys=True) + "\n",
    }
    reports_directory.mkdir(parents=True, exist_ok=True)
    targets = {name: reports_directory / name for name in contents}
    originals = {target: target.read_bytes() if target.exists() else None for target in targets.values()}
    temporary_paths = {}
    replaced = []
    try:
        for name, content in contents.items():
            target = targets[name]
            temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
            temporary.write_text(content, encoding="utf-8", newline="")
            temporary_paths[target] = temporary
        for target in targets.values():
            os.replace(temporary_paths[target], target)
            replaced.append(target)
    except OSError as error:
        for target in replaced:
            original = originals[target]
            if original is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(original)
        raise HealthMonitorError(f"Audit reports could not be written safely: {error}") from error
    finally:
        for temporary in temporary_paths.values():
            temporary.unlink(missing_ok=True)

    return (
        targets[INVENTORY_REPORT_NAME],
        targets[SUMMARY_REPORT_NAME],
        targets[SNAPSHOT_REPORT_NAME],
    )


def required_environment():
    names = ("ELASTIC_HEALTH_KEY", "ELASTIC_KIBANA_URL", "ELASTICSEARCH_URL")
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise HealthMonitorError(f"Missing required environment variables: {', '.join(missing)}")

    try:
        stale_after = int(os.environ.get("ELASTIC_HEALTH_DEFAULT_STALE_SECONDS", DEFAULT_STALE_AFTER_SECONDS))
        interval_multiplier = int(
            os.environ.get("ELASTIC_HEALTH_STALE_INTERVAL_MULTIPLIER", DEFAULT_STALE_INTERVAL_MULTIPLIER)
        )
    except ValueError as error:
        raise HealthMonitorError("Stale execution thresholds must be integers") from error
    if stale_after <= 0 or interval_multiplier <= 0:
        raise HealthMonitorError("Stale execution thresholds must be positive")

    return {
        "api_key": os.environ["ELASTIC_HEALTH_KEY"],
        "kibana_url": os.environ["ELASTIC_KIBANA_URL"],
        "elasticsearch_url": os.environ["ELASTICSEARCH_URL"],
        "space": os.environ.get("ELASTIC_SECURITY_SPACE", "default"),
        "lookback": os.environ.get("ELASTIC_ALERT_LOOKBACK", DEFAULT_LOOKBACK),
        "stale_after": stale_after,
        "interval_multiplier": interval_multiplier,
        "telemetry_freshness_seconds": telemetry_freshness_seconds(),
    }


def main():
    try:
        config = required_environment()
        headers = api_headers(config["api_key"])
        session = requests.Session()
        rules = get_rules(session, config["kibana_url"], config["space"], headers)
    except HealthMonitorError as error:
        print(f"ERROR: {error}")
        return 1

    alert_activity = None
    alert_error = None
    try:
        alert_activity = get_alert_activity(
            session,
            config["elasticsearch_url"],
            config["space"],
            headers,
            config["lookback"],
        )
    except HealthMonitorError as error:
        alert_error = str(error)

    generated_at = datetime.now(timezone.utc)
    telemetry_by_rule = None
    if not alert_error:
        telemetry_by_rule = collect_rule_telemetry(
            session,
            config["elasticsearch_url"],
            headers,
            rules,
            generated_at,
            config["telemetry_freshness_seconds"],
        )
    rows = build_rows(
        rules,
        alert_activity,
        alert_error,
        generated_at,
        config["stale_after"],
        config["interval_multiplier"],
        telemetry_by_rule,
    )
    print_report(rows, config["lookback"], alert_error)
    if alert_error:
        return 1

    try:
        inventory_path, summary_path, snapshot_path = write_audit_reports(rows, config["lookback"], generated_at)
    except HealthMonitorError as error:
        print(f"ERROR: {error}")
        return 1
    print(f"Audit reports written: {inventory_path}, {summary_path}, {snapshot_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
