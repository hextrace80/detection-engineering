"""Mocked safety tests for the human-confirmed AI findings PR helper."""

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "development" / "create_ai_findings_pr.py"
SPEC = importlib.util.spec_from_file_location("create_ai_findings_pr", SCRIPT_PATH)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class CreateAiFindingsPrTests(unittest.TestCase):
    def test_default_is_a_dry_run_after_showing_only_the_approved_file_diff(self):
        with patch.object(publisher, "_output", side_effect=["main", " M reports/approved_ai_findings.json", "safe diff"]), patch.object(publisher, "_run") as run:
            created = publisher.create_publication_pr("review/ai-findings-20261108", "Publish findings")
        self.assertFalse(created)
        run.assert_not_called()

    def test_confirmed_publication_stages_only_approved_findings_then_uses_gh_pr(self):
        with patch.object(publisher, "_output", side_effect=["main", " M reports/approved_ai_findings.json", "safe diff"]), patch.object(publisher, "_run", side_effect=[None, None, SimpleNamespace(returncode=1), None, None]) as run:
            created = publisher.create_publication_pr("review/ai-findings-20261108", "Publish findings", confirm=True)
        self.assertTrue(created)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn(["git", "add", "--", "reports/approved_ai_findings.json"], calls)
        self.assertIn(["git", "commit", "--only", "-m", "Publish findings", "--", "reports/approved_ai_findings.json"], calls)
        self.assertTrue(any(call[:3] == ["gh", "pr", "create"] and "--base" in call and "main" in call for call in calls))
        self.assertFalse(any(call[:2] == ["git", "push"] for call in calls))

    def test_refuses_non_main_or_unrelated_worktree_changes(self):
        with patch.object(publisher, "_output", return_value="feature/other"):
            with self.assertRaisesRegex(publisher.PublicationError, "main"):
                publisher.create_publication_pr("review/ai-findings-20261108", "Publish")
        with patch.object(publisher, "_output", side_effect=["main", " M development/health_agent.py"]):
            with self.assertRaisesRegex(publisher.PublicationError, "no changes other"):
                publisher.create_publication_pr("review/ai-findings-20261108", "Publish")


if __name__ == "__main__":
    unittest.main()
