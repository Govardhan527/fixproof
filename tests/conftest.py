import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from fixproof import cli
from scenario import KEV_FEED

GitRunner = Callable[..., str]


@pytest.fixture
def git_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, GitRunner]:
    """An empty repository whose git config ignores the machine's global and system config."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "Test Author")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "test@example.invalid")
    repo = tmp_path / "repo"
    repo.mkdir()

    def run(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    run("init", "--quiet", "--initial-branch=main")
    return repo, run


@pytest.fixture
def commit(git_repo: tuple[Path, GitRunner]) -> Callable[[str], str]:
    """Create an empty commit with the given message, bypassing hooks; return its SHA."""
    _, run = git_repo

    def make(message: str) -> str:
        run("commit", "--quiet", "--allow-empty", "--no-verify", "-m", message)
        return run("rev-parse", "HEAD")

    return make


@pytest.fixture(autouse=True)
def _kev_feed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests never reach cisa.gov: the CLI reads the real-feed excerpt instead."""
    monkeypatch.setattr(cli, "kev_fetcher", lambda url: KEV_FEED)
