"""The `fixproof` CLI end to end, with stand-in syft and grype on PATH (tests/scenario.py)."""

import json
import re
from pathlib import Path

import pytest

from fixproof import cli
from scenario import AUTHOR, FINISH, FIX_YAML, FIXED, SCOPE_YAML, START, VULNERABLE, install_tools
from tool_outputs import CVE

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    monkeypatch.setattr("sys.argv", ["fixproof", *args])
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    code = stopped.value.code
    assert isinstance(code, int)
    return code


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    install_tools(tmp_path, monkeypatch)
    ticks = iter([START, FINISH])
    monkeypatch.setattr(cli, "now", lambda: next(ticks))
    (tmp_path / "fix.yaml").write_text(FIX_YAML, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
    return {"fix": tmp_path / "fix.yaml", "scope": tmp_path / "scope.yaml", "out": tmp_path / "out"}


def verify_args(paths: dict[str, Path], *extra: str) -> list[str]:
    return [
        "verify", "--cve", CVE, "--fix", str(paths["fix"]), "--scope", str(paths["scope"]),
        "--out", str(paths["out"]), "--author", AUTHOR, *extra,
    ]  # fmt: skip


def test_verify_reports_each_image_and_exits_1_when_one_is_still_affected(
    inputs: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(monkeypatch, *verify_args(inputs)) == cli.EXIT_AFFECTED
    out = ANSI.sub("", capsys.readouterr().out)
    assert f"still_affected  {VULNERABLE.reference}" in out
    assert f"fixed           {FIXED.reference}" in out
    assert "1 fixed, 1 still_affected, 1 unknown; evidence in" in out
    vex = json.loads((inputs["out"] / "openvex.json").read_text())
    assert sorted(s["status"] for s in vex["statements"]) == [
        "affected",
        "fixed",
        "under_investigation",
    ]
    assert vex["timestamp"] == "2026-10-02T09:01:30Z"


def test_verify_json_summary(
    inputs: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(monkeypatch, *verify_args(inputs, "--json")) == cli.EXIT_AFFECTED
    report = json.loads(capsys.readouterr().out)
    assert report["summary"] == {"fixed": 1, "still_affected": 1, "unknown": 1}
    assert [a["verdict"] for a in report["assets"]] == ["still_affected", "fixed", "unknown"]
    assert report["assets"][0]["asset"] == VULNERABLE.reference


def test_exit_codes_follow_the_worst_verdict() -> None:
    from fixproof.model import Verdict

    assert cli.verdict_exit_code([Verdict.FIXED]) == 0
    assert cli.verdict_exit_code([Verdict.FIXED, Verdict.UNKNOWN]) == 2
    assert cli.verdict_exit_code([Verdict.UNKNOWN, Verdict.STILL_AFFECTED]) == 1


def test_all_fixed_exits_0(
    inputs: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs["scope"].write_text(
        f'schema_version: "1.0.0"\nregistries: [localhost:5001]\nimages: [{FIXED.reference}]\n',
        encoding="utf-8",
    )
    assert run(monkeypatch, *verify_args(inputs)) == cli.EXIT_FIXED
    assert "1 fixed, 0 still_affected, 0 unknown" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"--cve": "CVE-2099-0001"}, "the file is for CVE-2023-32681, not CVE-2099-0001"),
        ({"--author": " "}, "needs a non-empty author"),
    ],
)
def test_bad_input_exits_3(
    inputs: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    change: dict[str, str],
    message: str,
) -> None:
    args = verify_args(inputs)
    for flag, value in change.items():
        args[args.index(flag) + 1] = value
    assert run(monkeypatch, *args) == cli.EXIT_USAGE
    assert message in capsys.readouterr().err


def test_clusters_are_refused_until_they_are_supported(
    inputs: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs["scope"].write_text(
        SCOPE_YAML + "clusters:\n  - context: kind\n    namespaces: [demo]\n", encoding="utf-8"
    )
    assert run(monkeypatch, *verify_args(inputs)) == cli.EXIT_USAGE
    assert "clusters are not supported yet" in capsys.readouterr().err
    assert not inputs["out"].exists()


def test_existing_output_is_refused_before_any_tool_runs(
    inputs: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs["out"].mkdir()
    (inputs["out"] / "keep.txt").write_text("earlier evidence")
    monkeypatch.setenv("PATH", "/nonexistent")  # a tool run would fail loudly
    assert run(monkeypatch, *verify_args(inputs)) == cli.EXIT_USAGE
    assert "already exists and is not empty" in capsys.readouterr().err
    assert (inputs["out"] / "keep.txt").read_text() == "earlier evidence"


def test_usage_errors_exit_3_not_click_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(monkeypatch, "verify", "--bogus") == cli.EXIT_USAGE
    assert "No such option: --bogus" in ANSI.sub("", capsys.readouterr().err)


def test_version_and_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(monkeypatch, "--version") == 0
    assert capsys.readouterr().out.startswith("fixproof ")
    assert run(monkeypatch, "verify", "--help") == 0
    assert "--author" in ANSI.sub("", capsys.readouterr().out)
