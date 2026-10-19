"""Read-only operational health reporting for Elastic Security detections."""

import os
import sys
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote

import requests


RULES_PAGE_SIZE = 100
ALERT_BUCKET_PAGE_SIZE = 500
MAX_ALERT_BUCKET_PAGES = 10000
DEFAULT_LOOKBACK = "now-30d"
DEFAULT_STALE_AFTER_SECONDS = 900
DEFAULT_STALE_INTERVAL_MULTIPLIER = 3


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


def build_rows(rules, activity, alert_error, now, default_stale_after, interval_multiplier):
    rows = []
    for rule in rules:
        rule_uuid = rule.get("id")
        rule_activity = activity.get(rule_uuid) if activity is not None else None
        rows.append(
            {
                "name": rule.get("name", "<unnamed rule>"),
                "rule_id": rule.get("rule_id", "<missing rule_id>"),
                "status": classify_rule(rule, now, default_stale_after, interval_multiplier),
                "execution": last_execution_for_rule(rule),
                "alert_activity": rule_activity,
                "alert_error": alert_error,
            }
        )
    return rows


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

    rows = build_rows(
        rules,
        alert_activity,
        alert_error,
        datetime.now(timezone.utc),
        config["stale_after"],
        config["interval_multiplier"],
    )
    print_report(rows, config["lookback"], alert_error)
    return 1 if alert_error else 0


if __name__ == "__main__":
    sys.exit(main())
