"""The release gate (ADR-0012 items 1 to 3): closed.yaml, the image argument, verdicts, the CLI."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from fixproof import cli, kev
from fixproof.errors import InputError
from fixproof.gate import GateError, gate_asset, run_gate
from fixproof.inputs import ClosedFile, load_closed
from fixproof.model import BuildAsset, ImageAsset, Verdict
from fixproof.tools import ToolRun
from fixproof.validation import build_validator, load_schema, schema_errors
from scenario import BROKEN, FIXED, KEV_FEED, START, VULNERABLE, answers, install_tools
from tool_outputs import CVE, edited, image_runner, output, runner

ANSI = re.compile(r"\x1b\[[0-9;]*m")
LOG4SHELL = "CVE-2021-44228"  # closed too; in KEV (the real-feed excerpt)
CLOSED_YAML = f"""\
schema_version: "1.0.0"
registries: [localhost:5001]
closed:
  - cve: {CVE}
    packages:
      - ecosystem: pypi
        name: requests
        fixed_version: "2.31.0"
  - cve: {LOG4SHELL}
    packages:
      - ecosystem: maven
        namespace: org.apache.logging.log4j
        name: log4j-core
        fixed_version: "2.15.0"
"""
CLOSED = ClosedFile.model_validate(yaml.safe_load(CLOSED_YAML))
CATALOGUE = kev.load(START, lambda url: KEV_FEED)


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "closed.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# --- closed.yaml -----------------------------------------------------------------------------


def test_closed_yaml_reuses_the_fix_yaml_package_rules(tmp_path: Path) -> None:
    closed = load_closed(write(tmp_path, CLOSED_YAML))
    assert [entry.cve for entry in closed.closed] == [CVE, LOG4SHELL]
    assert closed.closed[1].fix.packages[0].purl == "pkg:maven/org.apache.logging.log4j/log4j-core"


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ('schema_version: "1.0.0"\nclosed: []\n', "closed: Tuple should have at least 1 item"),
        (CLOSED_YAML.replace(LOG4SHELL, CVE), "each CVE may be listed only once"),
        (
            CLOSED_YAML.replace("[localhost:5001]", "[localhost:5001, localhost:5001]"),
            "each registry may be listed only once",
        ),
        (
            CLOSED_YAML.replace("        namespace: org.apache.logging.log4j\n", ""),
            "namespace is required for maven packages",
        ),
        (
            CLOSED_YAML.replace(
                '        fixed_version: "2.31.0"\n',
                '        fixed_version: "2.31.0"\n      - ecosystem: pypi\n        name: requests\n'
                '        fixed_version: "2.31.0"\n',
            ),
            "each package may be listed only once",
        ),
        (CLOSED_YAML.replace(CVE, "CVE-23-1"), "String should match pattern"),
    ],
)
def test_bad_closed_yaml_is_refused_with_the_reason(
    tmp_path: Path, text: str, problem: str
) -> None:
    with pytest.raises(InputError) as raised:
        load_closed(write(tmp_path, text))
    assert problem in str(raised.value)


# --- the image argument ----------------------------------------------------------------------


def test_local_builds_and_digest_pinned_registry_images_are_accepted(tmp_path: Path) -> None:
    archive = tmp_path / "app.tar"
    archive.write_bytes(b"")
    assert gate_asset("docker:app:ci", CLOSED) == BuildAsset(source="docker:app:ci")
    for scheme in ("docker-archive:", "oci-archive:"):
        assert gate_asset(f"{scheme}{archive}", CLOSED) == BuildAsset(source=f"{scheme}{archive}")
    assert gate_asset(VULNERABLE.reference, CLOSED) == ImageAsset(image=VULNERABLE)
    assert gate_asset(f"registry:{VULNERABLE.reference}", CLOSED) == ImageAsset(image=VULNERABLE)


@pytest.mark.parametrize(
    ("image", "problem"),
    [
        ("docker:", "docker: needs an image name"),
        ("oci-archive:/no/such/app.tar", "no such file"),
        ("app:ci", "has no @sha256 digest"),
        ("app@sha256:" + "a" * 64, "has no registry host"),
        ("localhost:5001/fixproof/app:ci@sha256:" + "a" * 64, "has a tag"),
        ("registry.example.com/app@sha256:" + "a" * 64, "not in closed.yaml's registries"),
        ("podman:app:ci", "docker:NAME[:TAG], docker-archive:PATH or oci-archive:PATH"),
    ],
)
def test_other_image_arguments_are_refused(image: str, problem: str) -> None:
    with pytest.raises(GateError, match=re.escape(problem)):
        gate_asset(image, CLOSED)


# --- verdicts ---------------------------------------------------------------------------------


def counted(run: Any, calls: list[str]) -> Any:
    def wrapped(name: str, args: Any, env: Any) -> Any:
        calls.append(name)
        return run(name, args, env)

    return wrapped


def test_a_reintroduced_cve_is_still_affected_and_each_tool_runs_once() -> None:
    calls: list[str] = []
    result = run_gate(
        CLOSED, VULNERABLE.reference, CATALOGUE, counted(image_runner(answers()), calls)
    )
    assert sorted(calls) == ["grype", "syft"]  # once each, for two closed CVEs
    assert [(line.cve, line.verdict) for line in result.results] == [
        (CVE, Verdict.STILL_AFFECTED),
        (LOG4SHELL, Verdict.FIXED),
    ]
    assert result.results[1].kev.status == "listed"
    assert result.results[0].kev.status == "not_listed"
    assert result.summary.model_dump() == {"fixed": 1, "still_affected": 1, "unknown": 0}
    assert set(result.scanned) == {"grype", "sbom_version"}
    assert result.scanned["grype"]["image_id"] == result.scanned["sbom_version"]["image_id"]


def test_a_fixed_image_passes_and_an_unreadable_one_cannot_be_proven() -> None:
    fixed = run_gate(CLOSED, FIXED.reference, CATALOGUE, image_runner(answers()))
    assert {line.verdict for line in fixed.results} == {Verdict.FIXED}
    broken = run_gate(CLOSED, BROKEN.reference, CATALOGUE, image_runner(answers()))
    assert {line.verdict for line in broken.results} == {Verdict.UNKNOWN}
    assert broken.results[0].reason.startswith("grype failed")


def test_a_local_build_is_gated_where_it_was_built() -> None:
    calls: list[tuple[str, list[str], dict[str, str]]] = []
    documents = {"grype": output("grype", "vulnerable"), "syft": output("syft", "vulnerable")}
    result = run_gate(CLOSED, "docker:app:ci", CATALOGUE, runner(documents, calls))
    assert [call[1][0] for call in calls] == ["docker:app:ci", "docker:app:ci"]
    assert result.results[0].verdict is Verdict.STILL_AFFECTED
    assert result.scanned["grype"]["image_id"].startswith("sha256:")


def test_two_tools_reading_different_images_prove_nothing() -> None:
    syft = edited(
        output("syft", "vulnerable"),
        lambda d: d["source"]["metadata"].update(imageID="sha256:" + "0" * 64),
    )
    documents = {"grype": output("grype", "vulnerable"), "syft": syft}
    result = run_gate(CLOSED, "docker:app:ci", CATALOGUE, runner(documents))
    assert {line.verdict for line in result.results} == {Verdict.UNKNOWN}
    assert result.results[0].reason.startswith("the two tools read different images")


# --- the CLI ----------------------------------------------------------------------------------


def gate_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, image: str, *extra: str) -> int:
    install_tools(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "now", lambda: START)
    path = write(tmp_path, CLOSED_YAML)
    monkeypatch.setattr(
        "sys.argv", ["fixproof", "gate", "--closed", str(path), "--image", image, *extra]
    )
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    code = stopped.value.code
    assert isinstance(code, int)
    return code


def test_cli_blocks_a_release_that_brings_a_closed_cve_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert gate_cli(tmp_path, monkeypatch, VULNERABLE.reference) == cli.EXIT_AFFECTED
    out = ANSI.sub("", capsys.readouterr().out)
    assert f"still_affected  {CVE}  (not in CISA KEV)" in out
    assert f"fixed           {LOG4SHELL}  (in CISA KEV, due 2021-12-24)" in out
    assert "BLOCK: 1 of 2 closed CVEs are back in this image." in out


def test_cli_passes_a_clean_image_and_fails_one_it_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert gate_cli(tmp_path, monkeypatch, FIXED.reference) == cli.EXIT_FIXED
    assert "PASS: all 2 closed CVEs are proven gone from this image." in capsys.readouterr().out
    (tmp_path / "b").mkdir()
    assert gate_cli(tmp_path / "b", monkeypatch, BROKEN.reference) == cli.EXIT_UNKNOWN
    assert "CANNOT PROVE: 2 of 2 closed CVEs could not be checked" in capsys.readouterr().out


def test_cli_json_is_a_valid_gate_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert gate_cli(tmp_path, monkeypatch, VULNERABLE.reference, "--json") == cli.EXIT_AFFECTED
    result = json.loads(capsys.readouterr().out)
    assert schema_errors(build_validator(load_schema("gate-result.schema.json")), result) == []
    assert result["schema_version"] == "1.0.0"
    assert [line["verdict"] for line in result["results"]] == ["still_affected", "fixed"]


def test_cli_bad_input_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert gate_cli(tmp_path, monkeypatch, "app:ci") == cli.EXIT_USAGE
    assert "has no @sha256 digest" in capsys.readouterr().err


def test_tool_runs_are_cached_by_argument_list() -> None:
    from fixproof.gate import once_per_call

    seen: list[str] = []

    def run(name: str, args: Any, env: Any) -> ToolRun:
        seen.append(name)
        return ToolRun(0, b"{}", "")

    cached = once_per_call(run)
    cached("grype", ["a"], {})
    cached("grype", ["a"], {})
    cached("grype", ["b"], {})
    assert seen == ["grype", "grype"]


def test_an_unreachable_kev_feed_changes_no_gate_verdict_or_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def offline(url: str) -> bytes:
        raise kev.KevFetchError("cannot download the KEV feed: network is unreachable")

    monkeypatch.setattr(cli, "kev_fetcher", offline)
    assert gate_cli(tmp_path, monkeypatch, VULNERABLE.reference) == cli.EXIT_AFFECTED
    out = ANSI.sub("", capsys.readouterr().out)
    assert "KEV: unavailable (cannot download the KEV feed: network is unreachable)" in out
    assert f"still_affected  {CVE}  (CISA KEV unavailable)" in out
    assert "BLOCK: 1 of 2 closed CVEs are back in this image." in out
