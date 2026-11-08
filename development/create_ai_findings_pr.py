"""Create a human-confirmed PR containing only reviewed public AI findings."""

import argparse
import subprocess
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
APPROVED_FINDINGS = Path("reports") / "approved_ai_findings.json"


class PublicationError(Exception):
    """Raised before an unsafe or incomplete publication action."""


def _run(arguments, check=True):
    return subprocess.run(arguments, cwd=REPOSITORY_ROOT, text=True, capture_output=True, check=check)


def _output(arguments):
    result = _run(arguments)
    return result.stdout.strip()


def _validate_branch(branch):
    if not isinstance(branch, str) or not branch.startswith("review/ai-findings-") or any(character.isspace() for character in branch):
        raise PublicationError("Branch must start with review/ai-findings- and contain no whitespace")


def _validate_worktree():
    if _output(["git", "branch", "--show-current"]) != "main":
        raise PublicationError("Run this helper from the local main branch")
    changed = _output(["git", "status", "--porcelain", "--untracked-files=all"]).splitlines()
    expected_path = APPROVED_FINDINGS.as_posix()
    unexpected = [line for line in changed if line[3:].replace("\\", "/") != expected_path]
    if unexpected:
        raise PublicationError("Worktree must contain no changes other than reports/approved_ai_findings.json")
    if not changed:
        raise PublicationError("No approved findings change is available to publish")


def create_publication_pr(branch, title, confirm=False):
    """Show the one-file diff; mutate Git/GitHub state only with explicit confirmation."""
    _validate_branch(branch)
    _validate_worktree()
    findings_path = APPROVED_FINDINGS.as_posix()
    diff = _output(["git", "diff", "--", findings_path])
    print(diff or "No unstaged diff; the approved findings file may already be staged.")
    if not confirm:
        print("Dry run only. Review the diff, then rerun with --confirm to create the branch and pull request.")
        return False

    _run(["git", "switch", "-c", branch])
    _run(["git", "add", "--", findings_path])
    staged = _run(["git", "diff", "--cached", "--quiet", "--", findings_path], check=False)
    if staged.returncode == 0:
        raise PublicationError("No staged approved findings change is available to commit")
    _run(["git", "commit", "--only", "-m", title, "--", findings_path])
    _run([
        "gh", "pr", "create", "--base", "main", "--head", branch, "--title", title,
        "--body", "Human-reviewed, explicitly approved AI investigation findings only.",
    ])
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare a one-file, human-confirmed AI findings pull request.")
    parser.add_argument("--branch", required=True)
    parser.add_argument("--title", default="Publish reviewed AI detection-health findings")
    parser.add_argument("--confirm", action="store_true", help="Create a branch, commit the approved findings file, and open a PR.")
    arguments = parser.parse_args(argv)
    try:
        create_publication_pr(arguments.branch, arguments.title, arguments.confirm)
    except (PublicationError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
