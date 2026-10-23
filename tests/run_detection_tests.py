import json
import tomllib
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_FILE = REPOSITORY_ROOT / "tests" / "test_manifest.json"


def load_json(file_path):
    try:
        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError as error:
        raise ValueError(f"Missing JSON file: {file_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Malformed JSON in {file_path}: {error.msg}") from error


def load_toml(file_path):
    try:
        with file_path.open("rb") as file:
            return tomllib.load(file)
    except FileNotFoundError as error:
        raise ValueError(f"Missing TOML rule file: {file_path}") from error
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"Malformed TOML in {file_path}: {error}") from error


def check(condition, description):
    if condition:
        print(f"PASS: {description}")
        return True

    print(f"FAIL: {description}")
    return False


def get_mitre_ids(rule):
    mitre_ids = []

    for threat in rule.get("threat", []):
        for technique in threat.get("technique", []):
            mitre_ids.append(technique.get("id"))
            for subtechnique in technique.get("subtechnique", []):
                mitre_ids.append(subtechnique.get("id"))

    return [mitre_id for mitre_id in mitre_ids if mitre_id]


# Temporary simulated test adapters. These functions do not parse or execute
# Elastic KQL, and passing tests do not prove live Elastic detection behavior.
def matches_aws_iam_access_key_created(fixture):
    event = fixture["event"]

    return (
        event["dataset"] == "aws.cloudtrail"
        and event["provider"] == "iam.amazonaws.com"
        and event["action"] == "CreateAccessKey"
    )


def matches_scheduled_task_creation(fixture):
    event = fixture["event"]
    process = fixture["process"]

    categories = event["category"]
    if isinstance(categories, str):
        categories = [categories]

    return (
        "process" in categories
        and event["dataset"] == "windows.sysmon_operational"
        and process["name"] == "schtasks.exe"
        and "Create" in process["command_line"]
    )


def matches_linux_suspicious_crontab_edit(fixture):
    event = fixture["event"]
    process = fixture["process"]

    return (
        event["dataset"] == "auditd.log"
        and event["action"] == "execve"
        and process["executable"] == "crontab"
        and "-e" in process["args"]
    )


MATCHERS = {
    "aws_iam_access_key_created": matches_aws_iam_access_key_created,
    "scheduled_task_creation": matches_scheduled_task_creation,
    "linux_suspicious_crontab_edit": matches_linux_suspicious_crontab_edit,
}


def get_required_value(item, field, item_name):
    if field not in item:
        raise ValueError(f"Malformed manifest entry for {item_name}: missing '{field}'")
    return item[field]


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("Malformed manifest: root must be a JSON object")

    detections = manifest.get("detections")
    if not isinstance(detections, list) or not detections:
        raise ValueError("Malformed manifest: 'detections' must be a non-empty list")

    return detections


def run_detection_test(detection):
    if not isinstance(detection, dict):
        print("ERROR: Malformed manifest entry: each detection must be an object")
        return False

    try:
        name = get_required_value(detection, "name", "unknown detection")
        rule_file = get_required_value(detection, "rule_file", name)
        fixture_directory = get_required_value(detection, "fixture_directory", name)
        matcher_name = get_required_value(detection, "matcher", name)
        expected_metadata = get_required_value(detection, "expected_rule_metadata", name)
        query_fragments = get_required_value(detection, "expected_query_fragments", name)
        test_cases = get_required_value(detection, "test_cases", name)

        if not isinstance(expected_metadata, dict):
            raise ValueError(f"Malformed manifest entry for {name}: expected_rule_metadata must be an object")
        if not isinstance(query_fragments, list):
            raise ValueError(f"Malformed manifest entry for {name}: expected_query_fragments must be a list")
        if not isinstance(test_cases, list) or not test_cases:
            raise ValueError(f"Malformed manifest entry for {name}: test_cases must be a non-empty list")

        matcher = MATCHERS.get(matcher_name)
        if matcher is None:
            raise ValueError(f"Malformed manifest entry for {name}: unknown matcher '{matcher_name}'")

        rule_document = load_toml(REPOSITORY_ROOT / rule_file)
        rule = rule_document.get("rule")
        if not isinstance(rule, dict):
            raise ValueError(f"Malformed TOML rule file: {rule_file} is missing [rule]")
    except ValueError as error:
        print(f"ERROR: {error}")
        return False

    print(f"\nDetection: {name}")
    all_passed = True

    for field in ("severity", "risk_score", "index"):
        if field not in expected_metadata:
            print(f"ERROR: Malformed manifest entry for {name}: missing expected metadata '{field}'")
            return False
        all_passed = check(
            rule.get(field) == expected_metadata[field],
            f"Rule {field} matches the expected value",
        ) and all_passed

    expected_mitre_id = expected_metadata.get("mitre_id")
    if not isinstance(expected_mitre_id, str):
        print(f"ERROR: Malformed manifest entry for {name}: mitre_id must be a string")
        return False

    all_passed = check(
        expected_mitre_id in get_mitre_ids(rule),
        f"Rule includes MITRE ID {expected_mitre_id}",
    ) and all_passed

    query = rule.get("query", "")
    for query_fragment in query_fragments:
        if not isinstance(query_fragment, str):
            print(f"ERROR: Malformed manifest entry for {name}: query fragments must be strings")
            return False
        all_passed = check(
            query_fragment in query,
            f"Rule query contains: {query_fragment}",
        ) and all_passed

    fixture_root = REPOSITORY_ROOT / fixture_directory
    for test_case in test_cases:
        if not isinstance(test_case, dict):
            print(f"ERROR: Malformed manifest entry for {name}: each test case must be an object")
            return False

        fixture_name = test_case.get("fixture")
        expected_match = test_case.get("expected_match")
        if not isinstance(fixture_name, str) or not isinstance(expected_match, bool):
            print(f"ERROR: Malformed manifest entry for {name}: fixture and boolean expected_match are required")
            return False

        try:
            fixture = load_json(fixture_root / fixture_name)
            actual_match = matcher(fixture)
        except (KeyError, TypeError) as error:
            print(f"ERROR: Invalid fixture {fixture_name} for {name}: missing or invalid field {error}")
            return False
        except ValueError as error:
            print(f"ERROR: {error}")
            return False

        all_passed = check(
            actual_match == expected_match,
            f"{fixture_name}: expected match = {expected_match}, actual match = {actual_match}",
        ) and all_passed

    return all_passed


def main():
    try:
        detections = validate_manifest(load_json(MANIFEST_FILE))
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1

    all_passed = True
    for detection in detections:
        all_passed = run_detection_test(detection) and all_passed

    if all_passed:
        print("\nAll detection tests passed.")
        return 0

    print("\nOne or more detection tests failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
