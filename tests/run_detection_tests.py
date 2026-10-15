from pathlib import Path
import json
import tomllib
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "scheduled_task_creation_via_schtasks"
)
EXPECTATIONS_FILE = FIXTURE_DIRECTORY / "test_expectations.json"

def load_json(file_path):
    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_toml(file_path):
    with file_path.open("rb") as file:
        return tomllib.load(file)


def check(condition, description):
    if condition:
        print(f"PASS: {description}")
        return True

    print(f"FAIL: {description}")
    return False


def get_mitre_subtechnique_ids(rule):
    subtechnique_ids = []

    for threat in rule.get("threat", []):
        for technique in threat.get("technique", []):
            for subtechnique in technique.get("subtechnique", []):
                subtechnique_ids.append(subtechnique["id"])

    return subtechnique_ids



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



def main():
    expectations = load_json(EXPECTATIONS_FILE)

    rule_path = REPOSITORY_ROOT / expectations["rule_file"]
    rule_document = load_toml(rule_path)
    rule = rule_document["rule"]
    expected_metadata = expectations["expected_rule_metadata"]
    all_passed = True

    all_passed = check(
        rule["severity"] == expected_metadata["severity"],
        "Rule severity matches the expected value",
    ) and all_passed

    all_passed = check(
        rule["risk_score"] == expected_metadata["risk_score"],
        "Rule risk score matches the expected value",
    ) and all_passed    
    
    mitre_subtechnique_ids = get_mitre_subtechnique_ids(rule)

    all_passed = check(
        expected_metadata["mitre_subtechnique_id"] in mitre_subtechnique_ids,
        "Rule includes the expected MITRE sub-technique ID",
    ) and all_passed

    for query_fragment in expectations["expected_query_fragments"]:
        all_passed = check(
            query_fragment in rule["query"],
            f'Rule query contains: {query_fragment}',
        ) and all_passed


    for test_case in expectations["test_cases"]:
        fixture_name = test_case["fixture"]
        fixture_path = FIXTURE_DIRECTORY / fixture_name
        fixture = load_json(fixture_path)

        actual_match = matches_scheduled_task_creation(fixture)
        expected_match = test_case["expected_match"]

        all_passed = check(
            actual_match == expected_match,
            f"{fixture_name}: expected match = {expected_match}, actual match = {actual_match}",
        ) and all_passed    

    if all_passed:
        print("\nAll scheduled-task detection tests passed.")
        return 0

    print("\nOne or more scheduled-task detection tests failed.")
    return 1  

      


if __name__ == "__main__":
    sys.exit(main())