import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import GitRunner

HOOK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "commit-msg"


def run_hook(tmp_path: Path, message: str) -> subprocess.CompletedProcess[str]:
    message_file = tmp_path / "COMMIT_EDITMSG"
    message_file.write_text(message, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(HOOK), str(message_file)], capture_output=True, text=True, check=False
    )


def test_hook_is_executable() -> None:
    assert os.access(HOOK, os.X_OK)


def test_hook_accepts_a_conventional_message(tmp_path: Path) -> None:
    result = run_hook(tmp_path, "build(M0): add uv lock\n")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "message",
    [
        "feat(M0): x\n\nCo-authored-by: Pair Bot <bot@example.com>\n",
        "Initial commit\n",
    ],
)
def test_hook_rejects_bad_messages(tmp_path: Path, message: str) -> None:
    result = run_hook(tmp_path, message)
    assert result.returncode == 1
    assert result.stderr.startswith("commit rejected:")


def test_hook_rejects_a_real_commit(git_repo: tuple[Path, GitRunner]) -> None:
    repo, run = git_repo
    trailer = "Co-authored-by: Pair Bot <bot@example.com>"
    result = subprocess.run(
        [
            *("git", "-C", str(repo), "-c", f"core.hooksPath={HOOK.parent}", "commit"),
            *("--allow-empty", "-m", "feat(M0): x", "-m", trailer),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "commit rejected:" in result.stderr
    assert run("rev-list", "--all") == ""
