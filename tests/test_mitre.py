"""Mocked output and exit-status tests for development/mitre.py."""

import contextlib
import io
import os
import runpy
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "mitre.py"


class FakeResponse:
    def json(self):
        return {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Scheduled Task/Job",
                    "external_references": [{"external_id": "T1053", "url": "https://example.test/T1053"}],
                    "kill_chain_phases": [{"phase_name": "execution"}],
                }
            ]
        }


def detection_toml(technique_id="T1053", technique_name="Scheduled Task/Job"):
    return f'''[rule]
name = "test"
[[rule.threat]]
framework = "MITRE ATT&CK"
[rule.threat.tactic]
name = "Execution"
[[rule.threat.technique]]
id = "{technique_id}"
name = "{technique_name}"
'''


class MitreValidationTests(unittest.TestCase):
    def run_script(self, temporary_directory):
        output = io.StringIO()
        fake_requests = types.SimpleNamespace(get=lambda url, headers: FakeResponse())
        original_directory = os.getcwd()
        try:
            os.chdir(temporary_directory)
            with patch.dict(sys.modules, {"requests": fake_requests}):
                with contextlib.redirect_stdout(output):
                    try:
                        runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
                    except SystemExit as exited:
                        exit_code = exited.code
                    else:
                        exit_code = 0
        finally:
            os.chdir(original_directory)
        return exit_code, output.getvalue()

    def test_valid_detection_prints_one_pass_and_passing_summary(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            detections = Path(temporary_directory, "detections")
            detections.mkdir()
            Path(detections, "valid.toml").write_text(detection_toml(), encoding="utf-8")
            exit_code, output = self.run_script(temporary_directory)

        self.assertEqual(exit_code, 0)
        self.assertEqual(output.count("PASS: MITRE ATT&CK validation — valid.toml"), 1)
        self.assertIn("Total: 1", output)
        self.assertIn("Passed: 1", output)
        self.assertIn("Failed: 0", output)
        self.assertIn("Overall Result: PASS", output)

    def test_invalid_detection_prints_details_and_one_fail(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            detections = Path(temporary_directory, "detections")
            detections.mkdir()
            Path(detections, "invalid.toml").write_text(
                detection_toml("T0000", "Wrong Technique Name"), encoding="utf-8"
            )
            exit_code, output = self.run_script(temporary_directory)

        self.assertEqual(exit_code, 1)
        self.assertIn('Invalid MITRE Technique ID: "T0000"', output)
        self.assertIn("invalid.toml", output)
        self.assertEqual(output.count("FAIL: MITRE ATT&CK validation — invalid.toml"), 1)
        self.assertIn("Total: 1", output)
        self.assertIn("Passed: 0", output)
        self.assertIn("Failed: 1", output)
        self.assertIn("Overall Result: FAIL", output)

    def test_no_toml_files_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            Path(temporary_directory, "detections").mkdir()
            exit_code, output = self.run_script(temporary_directory)

        self.assertEqual(exit_code, 1)
        self.assertIn("no TOML detection files found", output)
        self.assertIn("Total: 0", output)
        self.assertIn("Overall Result: FAIL", output)


if __name__ == "__main__":
    unittest.main()
