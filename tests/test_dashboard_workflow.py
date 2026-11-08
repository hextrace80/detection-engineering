"""Structural tests for the isolated dashboard Pages workflow."""

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "detection_health_dashboard.yml"


class DashboardWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_has_daily_eastern_schedule_and_manual_modes(self):
        self.assertIn('cron: "0 9 * * *"', self.workflow)
        self.assertIn('timezone: "America/New_York"', self.workflow)
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("default: live", self.workflow)
        self.assertIn("- live", self.workflow)
        self.assertIn("- demo", self.workflow)

    def test_pull_requests_use_demo_mode_and_live_collection_uses_health_configuration(self):
        self.assertIn('"${{ github.event_name }}" == "pull_request"', self.workflow)
        self.assertIn("mode=demo", self.workflow)
        self.assertIn("ELASTIC_HEALTH_KEY: ${{ secrets.ELASTIC_HEALTH_KEY }}", self.workflow)
        self.assertEqual(self.workflow.count("secrets.ELASTIC_HEALTH_KEY"), 1)
        self.assertNotIn("secrets.ELASTIC_KEY", self.workflow)
        self.assertIn("ELASTIC_KIBANA_URL: ${{ vars.ELASTIC_KIBANA_URL }}", self.workflow)
        self.assertIn("ELASTICSEARCH_URL: ${{ vars.ELASTICSEARCH_URL }}", self.workflow)
        self.assertIn("ELASTIC_SECURITY_SPACE: ${{ vars.ELASTIC_SECURITY_SPACE }}", self.workflow)
        self.assertIn("if: steps.mode.outputs.mode == 'live'", self.workflow)

    def test_deployment_is_limited_to_authorized_main_runs(self):
        self.assertIn("needs: build", self.workflow)
        self.assertIn("github.ref == 'refs/heads/main'", self.workflow)
        self.assertIn("github.event_name == 'schedule'", self.workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'", self.workflow)
        self.assertIn("pages: write", self.workflow)
        self.assertIn("id-token: write", self.workflow)

    def test_workflow_is_separate_from_detection_deployment(self):
        self.assertNotIn("update_alert.py", self.workflow)
        self.assertNotIn("elastic_sync.yml", self.workflow)
        self.assertIn("tests/test_detection_health.py", self.workflow)
        self.assertIn("tests/test_detection_health_dashboard.py", self.workflow)
        self.assertIn("reports/approved_ai_findings.json", self.workflow)


if __name__ == "__main__":
    unittest.main()
