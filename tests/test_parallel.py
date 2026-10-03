"""Scanning several images at once (ADR-0011): the scans overlap, and the result does not change."""

import threading
from pathlib import Path
from typing import Any

import pytest
import yaml

from fixproof import cli
from fixproof.bundle import write_bundle
from fixproof.inputs import FixFile, ScopeFile
from fixproof.verify import DEFAULT_JOBS, assess
from fixproof.vex import build_document
from scenario import AUTHOR, FINISH, FIX_YAML, KEV, SCOPE_YAML, START, answers, install_tools
from test_verify_clusters import SCOPE_YAML as CLUSTER_SCOPE_YAML
from test_verify_clusters import Cluster
from tool_outputs import CVE, image_runner

FIX = FixFile.model_validate(yaml.safe_load(FIX_YAML))
SCOPE = ScopeFile.model_validate(yaml.safe_load(SCOPE_YAML))  # three distinct images


def gated_runner(parties: int, timeout: float = 10) -> Any:
    """A runner whose Grype calls wait until `parties` of them are running at the same time."""
    run, gate = image_runner(answers()), threading.Barrier(parties, timeout=timeout)

    def gated(name: str, args: Any, env: Any) -> Any:
        if name == "grype":
            gate.wait()  # BrokenBarrierError unless the scans really overlap
        return run(name, args, env)

    return gated


def counting_runner() -> tuple[Any, list[int]]:
    run, lock, state = image_runner(answers()), threading.Lock(), [0, 0]  # running, most seen

    def counted(name: str, args: Any, env: Any) -> Any:
        with lock:
            state[0] += 1
            state[1] = max(state[1], state[0])
        try:
            return run(name, args, env)
        finally:
            with lock:
                state[0] -= 1

    return counted, state


def test_images_are_scanned_at_the_same_time() -> None:
    verdicts = [a.verdict.verdict for a in assess(FIX, SCOPE, gated_runner(3), jobs=3)]
    assert len(verdicts) == 3


def test_the_gate_catches_scans_that_do_not_overlap() -> None:
    with pytest.raises(threading.BrokenBarrierError):
        assess(FIX, SCOPE, gated_runner(3, timeout=0.5), jobs=1)


def test_jobs_one_scans_one_image_at_a_time() -> None:
    run, state = counting_runner()
    assess(FIX, SCOPE, run, jobs=1)
    assert state[1] == 1


def bundle_bytes(out: Path, jobs: int, scope: ScopeFile, scope_yaml: str) -> dict[str, bytes]:
    assessments = assess(FIX, scope, image_runner(answers()), lambda context: Cluster(), jobs)
    vex = build_document(FIX, [a.verdict for a in assessments], author=AUTHOR, now=FINISH)
    write_bundle(
        out,
        cve=CVE,
        fix_bytes=FIX_YAML.encode(),
        scope_bytes=scope_yaml.encode(),
        assessments=assessments,
        vex=vex,
        started=START,
        finished=FINISH,
        kev=KEV,
    )
    return {str(p.relative_to(out)): p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}


@pytest.mark.parametrize("jobs", [2, DEFAULT_JOBS, 16])
def test_the_evidence_is_identical_for_any_number_of_jobs(tmp_path: Path, jobs: int) -> None:
    scope = ScopeFile.model_validate(yaml.safe_load(CLUSTER_SCOPE_YAML))  # images and workloads
    one = bundle_bytes(tmp_path / "one", 1, scope, CLUSTER_SCOPE_YAML)
    many = bundle_bytes(tmp_path / "many", jobs, scope, CLUSTER_SCOPE_YAML)
    assert one == many


def test_jobs_must_be_at_least_one() -> None:
    with pytest.raises(ValueError, match="jobs must be at least 1"):
        assess(FIX, SCOPE, image_runner(answers()), jobs=0)


def test_cli_refuses_jobs_below_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install_tools(tmp_path, monkeypatch)
    (tmp_path / "fix.yaml").write_text(FIX_YAML, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "fixproof", "verify", "--cve", CVE, "--fix", str(tmp_path / "fix.yaml"),
            "--scope", str(tmp_path / "scope.yaml"), "--out", str(tmp_path / "out"),
            "--author", AUTHOR, "--jobs", "0",
        ],
    )  # fmt: skip
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == cli.EXIT_USAGE
    assert "--jobs" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
