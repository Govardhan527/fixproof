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


def test_output_beyond_the_limit_stops_the_tool_and_is_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0013 item 3: a runaway output is cut off, never read whole, never a result."""
    yes = shutil.which("yes")
    assert yes is not None
    fake_tool(tmp_path, monkeypatch, "grype", f"exec {yes} match")  # writes forever
    run = run_tool("grype", [], {}, timeout=30, max_output=100_000)
    assert (run.exit_code, run.stdout) == (None, b"")
    assert run.problem == "grype wrote more than 100000 bytes of output"


def test_output_up_to_the_limit_is_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = shutil.which("head")
    yes = shutil.which("yes")
    assert head is not None
    assert yes is not None
    fake_tool(tmp_path, monkeypatch, "syft", f"{yes} x | {head} -c 100000")
    run = run_tool("syft", [], {}, max_output=100_000)
    assert (run.exit_code, run.problem, len(run.stdout)) == (0, None, 100_000)


def test_only_the_end_of_standard_error_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = shutil.which("head")
    yes = shutil.which("yes")
    assert head is not None
    assert yes is not None
    fake_tool(
        tmp_path, monkeypatch, "grype", f"{yes} e | {head} -c 200000 >&2; echo END >&2; exit 1"
    )
    run = run_tool("grype", [], {})
    assert run.exit_code == 1
    assert len(run.stderr) == 64 * 1024
    assert run.stderr.endswith("END\n")


def test_an_oversized_output_gives_unknown_never_fixed() -> None:
    """End to end through a method and the verdict rule (ADR-0013 item 3)."""
    from fixproof.methods import grype, sbom_version
    from fixproof.model import MethodStatus, Verdict
    from fixproof.tools import ToolRun
    from fixproof.verdict import combine
    from tool_outputs import ASSET, CVE, output, requests_fix, runner

    too_big = ToolRun(None, b"", "", "grype wrote more than 536870912 bytes of output")
    by_grype = grype.assess(ASSET, CVE, runner({"grype": too_big}))
    by_sbom = sbom_version.assess(ASSET, requests_fix(), runner({"syft": output("syft", "fixed")}))
    assert by_grype.result.status is MethodStatus.ERROR
    verdict = combine(ASSET, by_grype.result, by_sbom.result)
    assert verdict.verdict is Verdict.UNKNOWN
    assert "grype wrote more than 536870912 bytes of output" in verdict.reason
