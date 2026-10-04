"""Workloads in a cluster (ADR-0010): each image scanned once, a verdict per workload."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from fixproof import cli
from fixproof.bundle import write_bundle
from fixproof.cyclonedx import build_bom
from fixproof.inputs import FixFile, ScopeFile
from fixproof.inventory import ContainerInfo, PodInfo
from fixproof.model import ImageRef, Verdict, WorkloadAsset
from fixproof.report import verify_summary
from fixproof.validation import build_validator, load_schema, schema_errors
from fixproof.verify import assess
from fixproof.vex import build_document, image_purl
from scenario import (
    AUTHOR,
    BROKEN,
    FINISH,
    FIX_YAML,
    FIXED,
    KEV,
    START,
    VULNERABLE,
    answers,
    install_tools,
)
from tool_outputs import CVE, image_runner

PRIVATE = ImageRef(registry="registry.example.com", repository="team/app", digest=FIXED.digest)
SCOPE_YAML = f"""\
schema_version: "1.0.0"
registries: [localhost:5001]
images:
  - {VULNERABLE.reference}
clusters:
  - context: kind-fixproof
    namespaces: [demo]
"""
FIX = FixFile.model_validate(yaml.safe_load(FIX_YAML))
SCOPE = ScopeFile.model_validate(yaml.safe_load(SCOPE_YAML))
DEPLOYMENT = ("ReplicaSet", "api-7d9")


class Cluster:
    """Six workloads, as in the success test, plus a second replica of the vulnerable one."""

    def pods(self, namespace: str) -> list[PodInfo]:
        def pod(name: str, image_id: str, waiting: str | None = None) -> PodInfo:
            return PodInfo(name, (ContainerInfo("app", image_id, waiting),), DEPLOYMENT)

        return [
            pod("api-7d9-a", VULNERABLE.reference),
            pod("api-7d9-b", VULNERABLE.reference),
            pod("fixed-1", FIXED.reference),
            pod("broken-1", BROKEN.reference),
            pod("pending-1", "", waiting="ImagePullBackOff"),
            pod("private-1", PRIVATE.reference),
        ]

    def replica_set_controller(self, namespace: str, name: str) -> tuple[str, str]:
        return ("Deployment", "api")


def counting_runner(calls: list[tuple[str, str]]) -> Any:
    run = image_runner(answers())

    def counted(name: str, args: Any, env: Any) -> Any:
        calls.append((name, args[0]))
        return run(name, args, env)

    return counted


def test_each_workload_gets_its_image_verdict_and_each_image_is_scanned_once() -> None:
    calls: list[tuple[str, str]] = []
    assessments = assess(FIX, SCOPE, counting_runner(calls), lambda context: Cluster())
    assert sorted(calls) == sorted(
        [(tool, f"registry:{image.reference}") for tool in ("grype", "syft")
         for image in (VULNERABLE, FIXED, BROKEN)]
        + [("crane", "manifest") for _ in (VULNERABLE, FIXED, BROKEN)]
    )  # PRIVATE is outside the allowlist and is never read  # fmt: skip
    found = [
        (a.verdict.asset.location if isinstance(a.verdict.asset, WorkloadAsset) else "image",
         a.verdict.verdict)
        for a in assessments
    ]  # fmt: skip
    assert found == [
        ("image", Verdict.STILL_AFFECTED),
        ("kind-fixproof/demo/api-7d9-a/app", Verdict.STILL_AFFECTED),
        ("kind-fixproof/demo/api-7d9-b/app", Verdict.STILL_AFFECTED),
        ("kind-fixproof/demo/broken-1/app", Verdict.UNKNOWN),
        ("kind-fixproof/demo/fixed-1/app", Verdict.FIXED),
        ("kind-fixproof/demo/pending-1/app", Verdict.UNKNOWN),
        ("kind-fixproof/demo/private-1/app", Verdict.UNKNOWN),
    ]
    reasons = {a.verdict.asset.location: a.verdict.reason for a in assessments[1:]}  # type: ignore[union-attr]
    assert reasons["kind-fixproof/demo/pending-1/app"] == (
        "image digest not resolved: the container has not started (ImagePullBackOff)"
    )
    assert reasons["kind-fixproof/demo/private-1/app"] == (
        "registry not in scope: registry.example.com; fixproof did not read the image"
    )
    assert "grype failed" in reasons["kind-fixproof/demo/broken-1/app"]
    assert assessments[1].outcomes is assessments[0].outcomes
    assert assessments[1].verdict.asset.owner == "Deployment/api"  # type: ignore[union-attr]


def test_shared_evidence_is_written_once_and_vex_is_per_image(tmp_path: Path) -> None:
    assessments = assess(FIX, SCOPE, image_runner(answers()), lambda context: Cluster())
    verdicts = [a.verdict for a in assessments]
    vex = build_document(FIX, verdicts, author=AUTHOR, now=FINISH)
    out = tmp_path / "out"
    bundle = write_bundle(
        out,
        cve=CVE,
        fix_bytes=FIX_YAML.encode(),
        scope_bytes=SCOPE_YAML.encode(),
        assessments=assessments,
        vex=vex,
        cyclonedx=build_bom(FIX, [a.verdict for a in assessments], now=FINISH),
        started=START,
        finished=FINISH,
        kev=KEV,
    )
    assert sorted(str(p.relative_to(out / "raw")) for p in (out / "raw").iterdir()) == [
        "001-grype.json",
        "001-sbom_version.json",
        "004-sbom_version.json",  # broken-1: grype failed, so there is no grype output
        "005-grype.json",
        "005-sbom_version.json",
    ]
    refs = [[r.raw_ref for p in record.platforms for r in p.results] for record in bundle.assets]
    assert refs[0] == refs[1] == refs[2] == ["raw/001-grype.json", "raw/001-sbom_version.json"]
    assert bundle.summary.model_dump() == {"fixed": 1, "still_affected": 3, "unknown": 3}
    assert {s["products"][0]["@id"]: s["status"] for s in vex["statements"]} == {
        image_purl(VULNERABLE): "affected",
        image_purl(FIXED): "fixed",
        image_purl(BROKEN): "under_investigation",
        image_purl(PRIVATE): "under_investigation",
    }  # the pending pod has no image, so no product: it stays in the bundle and the report
    record = json.loads((out / "bundle.json").read_text())["assets"][1]["asset"]
    assert record["owner"] == "Deployment/api"
    assert record["pod"] == "api-7d9-a"


def test_summary_names_the_workload_and_its_owner() -> None:
    assessments = assess(FIX, SCOPE, image_runner(answers()), lambda context: Cluster())
    report = verify_summary(CVE, "out", [a.verdict for a in assessments], KEV)
    validator = build_validator(load_schema("verify-summary.schema.json"))
    assert schema_errors(validator, report.model_dump(mode="json")) == []
    image, workload, pending = report.assets[0], report.assets[1], report.assets[5]
    assert (image.workload, image.owner) == (None, None)
    assert (workload.workload, workload.owner, workload.asset) == (
        "kind-fixproof/demo/api-7d9-a/app",
        "Deployment/api",
        VULNERABLE.reference,
    )
    assert (pending.workload, pending.asset) == ("kind-fixproof/demo/pending-1/app", None)


def test_cli_prints_pod_names_owners_and_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install_tools(tmp_path, monkeypatch)
    monkeypatch.setattr("fixproof.verify.KubernetesSource", lambda context: Cluster())
    (tmp_path / "fix.yaml").write_text(FIX_YAML, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "fixproof", "verify", "--cve", CVE, "--fix", str(tmp_path / "fix.yaml"),
            "--scope", str(tmp_path / "scope.yaml"), "--out", str(tmp_path / "out"),
            "--author", AUTHOR,
        ],
    )  # fmt: skip
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == cli.EXIT_AFFECTED
    out = capsys.readouterr().out
    pad = " " * 16
    assert (
        f"still_affected  kind-fixproof/demo/api-7d9-b/app  Deployment/api\n"
        f"{pad}{VULNERABLE.reference}\n{pad}both methods find"
    ) in out
    assert (
        f"unknown         kind-fixproof/demo/pending-1/app  Deployment/api\n"
        f"{pad}image not resolved\n{pad}image digest not resolved"
    ) in out
    assert f"still_affected  {VULNERABLE.reference}\n{pad}both methods find" in out
    assert "1 fixed, 3 still_affected, 3 unknown; evidence in" in out
