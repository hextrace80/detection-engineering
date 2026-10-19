"""Legacy implementation retained as inert reference during the safe refactor.

It is superseded by the implementation below.
"""

"""
import requests
import os
import tomllib
import json

url = "https://my-security-project-ed39ef.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"

api_key =  os.environ['ELASTIC_KEY']

headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": "ApiKey " + api_key
}


changed_files = os.environ["CHANGED_FILES"]


for root, dirs, files in os.walk("detections/"):
    for file in files:
      if file in changed_files:
        if file.endswith(".toml"):
          full_path = os.path.join (root, file)
          with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                if alert ['rule'] ['type'] == "query" :
                     required_fields =[  'author','description', 'name','rule_id', 'risk_score','severity', 'type', 'from','index','query', 'threat'  ]
                
                elif  alert ['rule'] ['type'] == "eql" :
                    required_fields =[ 'author', 'description', 'name','rule_id', 'risk_score','severity', 'type','from', 'query','index', 'language', 'threat'  ]
                
                elif alert ['rule'] ['type'] == "threshold" :
                    required_fields =[ 'author', 'description', 'name','rule_id', 'risk_score','severity', 'type', 'from','query' ,'index','threshold', 'threat'  ]
                
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break


                payload = {
                  field: alert["rule"][field]
                  for field in required_fields
                  if field in alert["rule"]
                }

                payload["enabled"] = True

        


     
       

        rule_id = alert["rule"]["rule_id"]
        update_url=url + "?rule_id=" + rule_id
                
        
      
        
                
                
        
        response = requests.put(update_url, headers=headers, json=payload, timeout=30)
        print("PUT status:", response.status_code)
        print("PUT response:", response.text)
        
        if response.status_code == 404:
                print("Rule does not exist. Trying POST to create it.")
                response = requests.post(url, headers=headers, json=payload, timeout=30)
                print("POST status:", response.status_code)
                print("POST response:", response.text)

        response.raise_for_status()
        print(json.dumps(payload, indent=2))
        print(response.status_code)
        print(response.text)
            
        
            # elastic_data = requests.post(url, headers=headers, data=data).json()
            # print (elastic_data)
"""

"""Synchronize changed TOML detections to Elastic Security safely."""

import copy
import os
import shlex
import sys
import tomllib
from pathlib import Path, PurePosixPath

import requests


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RULES_ENDPOINT = "https://my-security-project-ed39ef.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_QUERY_LANGUAGE = "kuery"
DEFAULT_INTERVAL = "5m"
DEFAULT_TO = "now"

REQUIRED_FIELDS_BY_TYPE = {
    "query": {"author", "description", "name", "rule_id", "risk_score", "severity", "type", "from", "index", "query", "threat"},
    "eql": {"author", "description", "name", "rule_id", "risk_score", "severity", "type", "from", "index", "query", "language", "threat"},
    "threshold": {"author", "description", "name", "rule_id", "risk_score", "severity", "type", "from", "index", "query", "threshold", "threat"},
}

# Existing values are copied only from this request-field allowlist. Unknown
# response fields cause a safe failure rather than a potentially destructive
# full PUT update.
WRITABLE_RULE_FIELDS = {
    "actions", "alert_suppression", "anomaly_threshold", "author", "building_block_type", "data_view_id",
    "description", "enabled", "eql_options", "esql_query", "event_category_override", "exceptions_list",
    "false_positives", "filters", "from", "history_window_start", "index", "investigation_fields", "interval",
    "language", "license", "machine_learning_job_id", "max_signals", "meta", "name", "namespace",
    "new_terms_fields", "note", "output_index", "query", "references", "related_integrations",
    "required_fields", "risk_score", "risk_score_mapping", "rule_id", "rule_name_override", "saved_id",
    "setup", "severity", "severity_mapping", "tags", "threat", "threat_filters", "threat_index",
    "threat_language", "threat_mapping", "threat_query", "threshold", "timeline_id", "timeline_title",
    "timestamp_override", "timestamp_override_fallback_disabled", "to", "type",
}

READ_ONLY_RULE_FIELDS = {
    "created_at", "created_by", "created_by_profile_uid", "execution_summary", "id", "immutable",
    "is_customized", "is_immutable", "is_prebuilt", "legacy_investigation_fields", "monitoring", "revision",
    "rule_source", "updated_at", "updated_by", "updated_by_profile_uid", "version",
}


class DeploymentError(Exception):
    """Raised for a safe, actionable deployment failure."""


def request_headers(api_key):
    return {
        "Content-Type": "application/json;charset=UTF-8",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {api_key}",
    }


def response_detail(response):
    text = response.text.strip()
    return text[:500] if text else "no response body"


def response_json(response, context):
    try:
        payload = response.json()
    except ValueError as error:
        raise DeploymentError(f"{context}: Elastic returned a non-JSON response") from error
    if not isinstance(payload, dict):
        raise DeploymentError(f"{context}: Elastic returned an unexpected JSON response")
    return payload


def request_rule(session, method, *, params=None, payload=None, headers=None):
    try:
        return getattr(session, method)(
            RULES_ENDPOINT, params=params, json=payload, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS
        )
    except requests.RequestException as error:
        raise DeploymentError(f"{method.upper()} rule request failed: {error}") from error


def get_existing_rule(session, rule_id, headers):
    response = request_rule(session, "get", params={"rule_id": rule_id}, headers=headers)
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise DeploymentError(f"GET rule {rule_id} failed with HTTP {response.status_code}: {response_detail(response)}")
    return response_json(response, f"GET rule {rule_id}")


def validate_toml_rule(rule, source_path):
    if not isinstance(rule, dict):
        raise DeploymentError(f"{source_path}: missing [rule] table")
    rule_type = rule.get("type")
    if rule_type not in REQUIRED_FIELDS_BY_TYPE:
        raise DeploymentError(f"{source_path}: unsupported rule type '{rule_type}'")
    missing_fields = sorted(REQUIRED_FIELDS_BY_TYPE[rule_type] - set(rule))
    if missing_fields:
        raise DeploymentError(f"{source_path}: missing required fields {missing_fields}")
    unmanaged_fields = sorted(set(rule) - WRITABLE_RULE_FIELDS)
    if unmanaged_fields:
        raise DeploymentError(f"{source_path}: unsupported TOML rule fields {unmanaged_fields}; refusing to omit them")


def toml_payload(rule, *, is_new):
    payload = {
        field: copy.deepcopy(value)
        for field, value in rule.items()
        if field in WRITABLE_RULE_FIELDS and field != "enabled"
    }
    if rule["type"] == "query":
        payload.setdefault("language", DEFAULT_QUERY_LANGUAGE)
    if is_new:
        payload.setdefault("interval", DEFAULT_INTERVAL)
        payload.setdefault("to", DEFAULT_TO)
        payload["enabled"] = True
    return payload


def build_update_payload(existing_rule, toml_rule, source_path):
    unknown_fields = sorted(set(existing_rule) - WRITABLE_RULE_FIELDS - READ_ONLY_RULE_FIELDS)
    if unknown_fields:
        raise DeploymentError(
            f"{source_path}: Elastic returned unclassified rule fields {unknown_fields}; "
            "refusing to update because a full PUT could lose configuration"
        )
    if existing_rule.get("rule_id") != toml_rule["rule_id"]:
        raise DeploymentError(f"{source_path}: retrieved rule_id does not match the TOML rule_id")
    if existing_rule.get("type") != toml_rule["type"]:
        raise DeploymentError(
            f"{source_path}: changing a rule type from '{existing_rule.get('type')}' to '{toml_rule['type']}' is unsupported"
        )
    if "enabled" not in existing_rule:
        raise DeploymentError(f"{source_path}: existing rule has no enabled state to preserve")

    payload = {
        field: copy.deepcopy(value)
        for field, value in existing_rule.items()
        if field in WRITABLE_RULE_FIELDS
    }
    payload.update(toml_payload(toml_rule, is_new=False))
    payload["enabled"] = existing_rule["enabled"]
    return payload


def verify_rule(rule_id, expected_payload, session, headers):
    actual_rule = get_existing_rule(session, rule_id, headers)
    if actual_rule is None:
        raise DeploymentError(f"POST/PUT rule {rule_id} appeared to succeed, but the rule was not found")
    mismatched_fields = [
        field for field, expected_value in expected_payload.items() if actual_rule.get(field) != expected_value
    ]
    if mismatched_fields:
        raise DeploymentError(
            f"Post-deployment verification failed for rule {rule_id}; "
            f"mismatched fields: {', '.join(sorted(mismatched_fields))}"
        )


def changed_detection_paths(changed_files, repository_root):
    try:
        changed_paths = shlex.split(changed_files)
    except ValueError as error:
        raise DeploymentError(f"CHANGED_FILES could not be parsed: {error}") from error
    paths = []
    for changed_path in changed_paths:
        relative_path = PurePosixPath(changed_path.replace("\\", "/"))
        if relative_path.suffix != ".toml" or relative_path.parts[:1] != ("detections",):
            continue
        if ".." in relative_path.parts:
            raise DeploymentError(f"Unsafe changed detection path: {changed_path}")
        paths.append(repository_root.joinpath(*relative_path.parts))
    return paths


def load_rule(source_path):
    try:
        with source_path.open("rb") as toml_file:
            document = tomllib.load(toml_file)
    except FileNotFoundError as error:
        raise DeploymentError(f"{source_path}: changed detection file is missing; automatic deletion is not supported") from error
    except tomllib.TOMLDecodeError as error:
        raise DeploymentError(f"{source_path}: malformed TOML: {error}") from error
    rule = document.get("rule")
    validate_toml_rule(rule, source_path)
    return rule


def deploy_rule(source_path, session, headers):
    rule = load_rule(source_path)
    rule_id = rule["rule_id"]
    existing_rule = get_existing_rule(session, rule_id, headers)
    if existing_rule is None:
        operation = "created"
        payload = toml_payload(rule, is_new=True)
        response = request_rule(session, "post", payload=payload, headers=headers)
        expected_statuses = {200, 201}
    else:
        operation = "updated"
        payload = build_update_payload(existing_rule, rule, source_path)
        response = request_rule(session, "put", params={"rule_id": rule_id}, payload=payload, headers=headers)
        expected_statuses = {200}
    if response.status_code not in expected_statuses:
        raise DeploymentError(
            f"{operation.title()} rule {rule_id} failed with HTTP {response.status_code}: {response_detail(response)}"
        )
    response_json(response, f"{operation.title()} rule {rule_id}")
    verify_rule(rule_id, payload, session, headers)
    return operation, rule_id


def deploy_changed_rules(changed_files, api_key, *, session=None, repository_root=REPOSITORY_ROOT):
    if not api_key:
        raise DeploymentError("ELASTIC_KEY is required")
    source_paths = changed_detection_paths(changed_files, repository_root)
    if not source_paths:
        raise DeploymentError("No changed detection TOML files were supplied")
    session = session or requests.Session()
    headers = request_headers(api_key)
    results = []
    for source_path in source_paths:
        try:
            operation, rule_id = deploy_rule(source_path, session, headers)
            results.append((source_path, rule_id, operation, None))
        except DeploymentError as error:
            results.append((source_path, None, "failed", str(error)))
    return results


def print_results(results):
    for source_path, rule_id, operation, error in results:
        if error:
            print(f"FAIL: {source_path}: {error}")
        else:
            print(f"PASS: {source_path}: {operation} rule {rule_id} and verified it")


def main():
    try:
        results = deploy_changed_rules(os.environ.get("CHANGED_FILES", ""), os.environ.get("ELASTIC_KEY", ""))
    except DeploymentError as error:
        print(f"ERROR: {error}")
        return 1
    print_results(results)
    return 0 if all(error is None for _, _, _, error in results) else 1


if __name__ == "__main__":
    sys.exit(main())
