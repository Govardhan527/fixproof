from collections.abc import Callable
from pathlib import Path

import pytest

from check_commits import main
from conftest import GitRunner

BAD_TRAILER = "feat(M1): add model\n\nCo-authored-by: Pair Bot <bot@example.com>\n"
ZERO_SHA = "0" * 40


def test_crafted_bad_range_fails(
    git_repo: tuple[Path, GitRunner],
    commit: Callable[[str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _ = git_repo
    base = commit("chore(M0): base")
    commit("feat(M1): good change")
    bad = commit(BAD_TRAILER)
    commit("Fix typo")

    assert main(["--repo", str(repo), "--base", base, "--head", "HEAD"]) == 1

    out = capsys.readouterr().out
    assert bad[:12] in out
    assert "forbidden attribution matched" in out
    assert "'Fix typo'" in out
    assert "checked 3 commit(s); 2 broke the commit rules" in out


def test_clean_range_passes(
    git_repo: tuple[Path, GitRunner],
    commit: Callable[[str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _ = git_repo
    base = commit("Initial commit")  # outside the range, so never checked
    commit("feat(M1): good change")
    commit("test(M1): cover it")

    assert main(["--repo", str(repo), "--base", base, "--head", "HEAD"]) == 0
    assert "checked 2 commit(s); 0 broke" in capsys.readouterr().out


def test_new_branch_checks_only_commits_not_on_origin_main(
    git_repo: tuple[Path, GitRunner], commit: Callable[[str], str]
) -> None:
    repo, run = git_repo
    main_tip = commit("Initial commit")  # already on origin/main: must not be checked
    run("update-ref", "refs/remotes/origin/main", main_tip)
    run("switch", "--quiet", "--create", "feature")
    commit("feat(M1): good change")
    args = ["--repo", str(repo), "--base", ZERO_SHA, "--head", "feature"]

    assert main(args) == 0

    commit(BAD_TRAILER)
    assert main(args) == 1


def test_new_branch_without_origin_main_checks_every_commit(
    git_repo: tuple[Path, GitRunner], commit: Callable[[str], str]
) -> None:
    repo, _ = git_repo
    commit("Initial commit")
    commit("feat(M1): good change")

    assert main(["--repo", str(repo), "--base", ZERO_SHA]) == 1


def test_missing_base_defaults_to_origin_main(
    git_repo: tuple[Path, GitRunner], commit: Callable[[str], str]
) -> None:
    repo, run = git_repo
    run("update-ref", "refs/remotes/origin/main", commit("Initial commit"))
    commit(BAD_TRAILER)

    assert main(["--repo", str(repo)]) == 1


def test_empty_range_passes_and_says_so(
    git_repo: tuple[Path, GitRunner],
    commit: Callable[[str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _ = git_repo
    tip = commit("feat(M1): good change")

    assert main(["--repo", str(repo), "--base", tip, "--head", tip]) == 0
    assert "checked 0 commit(s)" in capsys.readouterr().out


def test_unknown_base_is_an_error_not_a_pass(
    git_repo: tuple[Path, GitRunner],
    commit: Callable[[str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _ = git_repo
    commit("feat(M1): good change")

    assert main(["--repo", str(repo), "--base", "1" * 40]) == 2
    assert "check_commits: git rev-list" in capsys.readouterr().err
