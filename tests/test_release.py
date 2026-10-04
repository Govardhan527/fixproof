"""The release path (ADR-0013 item 5 and Amendment 2): the tag workflow builds and creates the
GitHub release but uploads nothing and holds no PyPI token; `scripts/publish.sh` uploads exactly
the files the release's SHA256SUMS names, after `twine check`, and never uploads a pre-release.

`publish.sh` runs here against fake `gh` and `uvx` commands, so no network and no credentials
are involved; the fakes record every call.
"""

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PUBLISH = ROOT / "scripts" / "publish.sh"
WHEEL = "fixproof-0.1.0-py3-none-any.whl"
SDIST = "fixproof-0.1.0.tar.gz"

FAKE_GH = """#!/usr/bin/env bash
echo "gh $*" >> "$FAKE_LOG"
if [[ "$1 $2" == "release view" ]]; then
  echo "$FAKE_PRERELEASE"
elif [[ "$1 $2" == "release download" ]]; then
  while [[ $# -gt 0 && "$1" != "--dir" ]]; do shift; done
  cp "$FAKE_ASSETS"/* "$2"/
fi
"""
FAKE_UVX = """#!/usr/bin/env bash
echo "uvx $*" >> "$FAKE_LOG"
if [[ "$*" == *" check "* ]]; then exit "${FAKE_CHECK_EXIT:-0}"; fi
"""


def _workflow() -> dict[Any, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return loaded


def test_the_workflow_runs_on_version_tags_only() -> None:
    # PyYAML reads the `on` key as the boolean True (YAML 1.1)
    assert _workflow()[True] == {"push": {"tags": ["v*"]}}


def test_the_workflow_uploads_nothing_and_holds_no_pypi_token() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    for absent in ("id-token", "secrets.", "gh-action-pypi-publish", "twine", "pypi.org"):
        assert absent not in text, absent
    assert sorted(_workflow()["jobs"]) == ["build", "github-release"]


def test_the_github_release_waits_for_the_checked_build() -> None:
    jobs = _workflow()["jobs"]
    assert jobs["github-release"]["needs"] == "build"
    assert "if" not in jobs["github-release"]
    names = [step.get("name", "") for step in jobs["build"]["steps"]]
    for check in (
        "Check the tag is the project's canonical version",
        "Check the tagged commit is on main and its CI run there passed",
        "Build, install in a fresh environment and check the wheel",
    ):
        assert check in names, check


def test_the_package_check_runs_twine_check() -> None:
    script = (ROOT / "scripts" / "check_package.sh").read_text(encoding="utf-8")
    assert 'uvx --from twine==7.0.0 twine check --strict "$work"/dist/*' in script


@pytest.fixture
def release(tmp_path: Path) -> dict[str, Path]:
    """A fake GitHub release for v0.1.0: the two packages and their SHA256SUMS."""
    assets = tmp_path / "assets"
    assets.mkdir()
    for name in (WHEEL, SDIST):
        (assets / name).write_bytes(f"contents of {name}".encode())
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("gh", FAKE_GH), ("uvx", FAKE_UVX)):
        (bin_dir / name).write_text(body, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    _write_sums(assets, [WHEEL, SDIST])
    return {"assets": assets, "bin": bin_dir, "log": tmp_path / "calls.log"}


def _write_sums(assets: Path, names: list[str]) -> None:
    lines = []
    for name in names:
        path = assets / name
        digest = hashlib.sha256(path.read_bytes() if path.exists() else b"").hexdigest()
        lines.append(f"{digest}  ./{name}\n")
    (assets / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def _publish(
    release: dict[str, Path], tag: str = "v0.1.0", prerelease: str = "false", check_exit: int = 0
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    env = {
        **os.environ,
        "PATH": f"{release['bin']}{os.pathsep}{os.environ['PATH']}",
        "FAKE_ASSETS": str(release["assets"]),
        "FAKE_LOG": str(release["log"]),
        "FAKE_PRERELEASE": prerelease,
        "FAKE_CHECK_EXIT": str(check_exit),
    }
    done = subprocess.run([str(PUBLISH), tag], capture_output=True, text=True, env=env, check=False)
    log = release["log"]
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return done, calls


def _twine(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("uvx ")]


def test_publish_uploads_exactly_the_checked_packages(release: dict[str, Path]) -> None:
    done, calls = _publish(release)
    assert done.returncode == 0, done.stderr
    assert calls[0] == (
        "gh release view v0.1.0 --repo Govardhan527/fixproof --json isPrerelease --jq .isPrerelease"
    )
    assert calls[1].startswith("gh release download v0.1.0 --repo Govardhan527/fixproof --dir ")
    assert _twine(calls) == [
        f"uvx --from twine==7.0.0 twine check --strict {WHEEL} {SDIST}",
        f"uvx --from twine==7.0.0 twine upload --non-interactive {WHEEL} {SDIST}",
    ]
    assert f"uploaded {WHEEL} {SDIST} to PyPI" in done.stdout


@pytest.mark.parametrize("prerelease", ["true", ""])
def test_publish_checks_a_pre_release_and_never_uploads_it(
    release: dict[str, Path], prerelease: str
) -> None:
    done, calls = _publish(release, prerelease=prerelease)
    assert done.returncode == 0, done.stderr
    assert _twine(calls) == [f"uvx --from twine==7.0.0 twine check --strict {WHEEL} {SDIST}"]
    assert "pre-release: its packages are checked and not uploaded" in done.stdout


def test_publish_refuses_a_package_that_does_not_match_its_sum(release: dict[str, Path]) -> None:
    (release["assets"] / WHEEL).write_bytes(b"tampered")
    done, calls = _publish(release)
    assert done.returncode != 0
    assert "FAILED" in done.stdout
    assert _twine(calls) == []


@pytest.mark.parametrize(
    "names",
    [[WHEEL], [WHEEL, SDIST, "fixproof-0.1.0-extra.whl"], [WHEEL, "fixproof-0.0.9.tar.gz"]],
)
def test_publish_refuses_sums_that_name_other_files(
    release: dict[str, Path], names: list[str]
) -> None:
    _write_sums(release["assets"], names)
    done, calls = _publish(release)
    assert done.returncode == 1
    assert "SHA256SUMS lists" in done.stderr
    assert _twine(calls) == []


def test_publish_refuses_a_missing_package(release: dict[str, Path]) -> None:
    (release["assets"] / SDIST).unlink()
    done, calls = _publish(release)
    assert done.returncode != 0
    assert _twine(calls) == []


def test_publish_stops_when_twine_check_fails(release: dict[str, Path]) -> None:
    done, calls = _publish(release, check_exit=1)
    assert done.returncode == 1
    assert _twine(calls) == [f"uvx --from twine==7.0.0 twine check --strict {WHEEL} {SDIST}"]


@pytest.mark.parametrize("tag", ["0.1.0", "v", ""])
def test_publish_refuses_a_bad_tag_before_calling_anything(
    release: dict[str, Path], tag: str
) -> None:
    done, calls = _publish(release, tag=tag)
    assert done.returncode != 0
    assert calls == []


def test_publish_is_executable() -> None:
    assert os.access(PUBLISH, os.X_OK)
