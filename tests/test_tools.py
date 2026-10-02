import os
import shutil
import stat
from pathlib import Path

import pytest

from fixproof.tools import last_line, run_tool


def fake_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, body: str) -> None:
    """Put an executable `name` on a PATH that holds nothing else."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / name
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(bin_dir))


def test_runs_the_tool_with_the_extra_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_tool(tmp_path, monkeypatch, "grype", 'echo "$1 $FIXPROOF_PROBE"; echo warn >&2')
    run = run_tool("grype", ["registry:x"], {"FIXPROOF_PROBE": "seen"})
    assert (run.exit_code, run.stdout, run.stderr, run.problem) == (
        0,
        b"registry:x seen\n",
        "warn\n",
        None,
    )


def test_inherits_the_callers_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tool(tmp_path, monkeypatch, "syft", 'echo "$DOCKER_CONFIG"')
    monkeypatch.setenv("DOCKER_CONFIG", "/run/creds")
    assert run_tool("syft", [], {}).stdout == b"/run/creds\n"


def test_reports_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tool(tmp_path, monkeypatch, "grype", "echo 'ERROR db too old' >&2; exit 1")
    run = run_tool("grype", [], {})
    assert (run.exit_code, run.problem, last_line(run.stderr)) == (1, None, "ERROR db too old")


def test_missing_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    assert run_tool("grype", [], {}).problem == "grype not found on PATH"


def test_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sleep = shutil.which("sleep")
    assert sleep is not None
    fake_tool(tmp_path, monkeypatch, "syft", f"exec {sleep} 5")
    run = run_tool("syft", [], {}, timeout=0.2)
    assert (run.exit_code, run.problem) == (None, "syft timed out after 0.2 seconds")


def test_unstartable_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tool(tmp_path, monkeypatch, "syft", "")
    (tmp_path / "bin" / "syft").write_bytes(b"\x7fELF-not-really")
    problem = run_tool("syft", [], {}).problem
    assert problem is not None
    assert problem.startswith("syft could not start: ")


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("", "no error output"),
        ("one\n\n  two  \n\n", "two"),
        ("\x1b[31mERROR\x1b[0m failed", "ERROR failed"),
        # Built at runtime so no credential-shaped literal sits in the repository.
        (
            f"GET https://{'alice'}:{'pw' * 3}@registry.example/v2/ failed",
            "GET https://***@registry.example/v2/ failed",
        ),
        ("x" * 300, "x" * 197 + "..."),
    ],
)
def test_last_line(stderr: str, expected: str) -> None:
    assert last_line(stderr) == expected


def test_environment_is_not_modified_for_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_tool(tmp_path, monkeypatch, "syft", "true")
    run_tool("syft", [], {"SYFT_CHECK_FOR_APP_UPDATE": "false"})
    assert "SYFT_CHECK_FOR_APP_UPDATE" not in os.environ
