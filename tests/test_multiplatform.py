"""Multi-platform images end to end (ADR-0014): verify, the bundle, the summary, the console, the
HTML page, the VEX and the gate.

`fixproof/multi` is an image index of three platforms whose tool outputs differ: linux/amd64 has
the fixed `requests`, linux/arm64 the vulnerable one, and Grype cannot read linux/arm/v6. So the
image is `still_affected`, each platform has its own verdict, and none is hidden.
"""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fixproof import htmlreport
from fixproof.bundle import write_bundle
from fixproof.cli import _gate_human, _human
from fixproof.cyclonedx import build_bom
from fixproof.gate import run_gate
from fixproof.inputs import ClosedFile, FixFile, ScopeFile
from fixproof.model import ImageRef, Verdict
from fixproof.report import verify_summary
from fixproof.tools import ToolRun
from fixproof.validation import build_validator, load_schema, schema_errors
from fixproof.verify import assess
from fixproof.vex import build_document
from scenario import AUTHOR, BROKEN_RUN, FINISH, KEV, START
from tool_outputs import CVE, for_image, image_runner, index_digest, manifest_digest, output

REPOSITORY = "fixproof/multi"
PLATFORMS = {"linux/amd64": "fixed", "linux/arm64": "vulnerable", "linux/arm/v6": "broken"}
CHILD = {name: manifest_digest(f"{REPOSITORY} {name}") for name in PLATFORMS}
INDEX = index_digest([(digest, name) for name, digest in CHILD.items()])
MULTI = ImageRef(registry="localhost:5001", repository=REPOSITORY, digest=INDEX)
FIX = FixFile.model_validate(
    {
        "schema_version": "1.0.0",
        "cve": CVE,
        "packages": [{"ecosystem": "pypi", "name": "requests", "fixed_version": "2.31.0"}],
    }
)


def child(name: str) -> ImageRef:
    return ImageRef(registry="localhost:5001", repository=REPOSITORY, digest=CHILD[name])


def as_platform(document: dict[str, Any], name: str) -> dict[str, Any]:
    """The tool output as if read from that platform's manifest."""
    os_name, arch, *variant = name.split("/")
    changed = for_image(document, child(name))
    metadata = changed["source"]["metadata" if "artifacts" in changed else "target"]
    metadata.update(os=os_name, architecture=arch, manifestDigest=CHILD[name])
    if variant:
        metadata["architectureVariant"] = variant[0]  # Syft's key (SPEC_NOTES §20)
    return changed


def answers() -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for name, state in PLATFORMS.items():
        syft = as_platform(output("syft", "fixed" if state == "broken" else state), name)
        grype = BROKEN_RUN if state == "broken" else as_platform(output("grype", state), name)
        found[child(name).reference] = {"syft": syft, "grype": grype}
    return found


def counted(calls: list[tuple[str, str]]) -> Any:
    run = image_runner(answers())

    def wrapped(name: str, args: Sequence[str], env: Mapping[str, str]) -> ToolRun:
        calls.append((name, args[1] if name == "crane" else args[0]))
        return run(name, args, env)

    return wrapped


def scope(platforms: list[str] | None = None) -> ScopeFile:
    extra = {"schema_version": "1.1.0", "platforms": platforms} if platforms else {}
    base = {"schema_version": "1.0.0", "registries": ["localhost:5001"]}
    return ScopeFile.model_validate({**base, "images": [MULTI.reference], **extra})


def test_every_platform_is_checked_and_the_affected_one_decides() -> None:
    calls: list[tuple[str, str]] = []
    (assessment,) = assess(FIX, scope(), counted(calls))
    verdict = assessment.verdict
    assert verdict.verdict is Verdict.STILL_AFFECTED
    assert [(p.platform, p.digest, p.verdict) for p in verdict.platforms] == [
        ("linux/amd64", CHILD["linux/amd64"], Verdict.FIXED),
        ("linux/arm64", CHILD["linux/arm64"], Verdict.STILL_AFFECTED),
        ("linux/arm/v6", CHILD["linux/arm/v6"], Verdict.UNKNOWN),
    ]
    assert verdict.reason.startswith(
        "3 platforms checked: linux/amd64 fixed, linux/arm64 still_affected, linux/arm/v6 unknown. "
        "linux/amd64: both methods agree the vulnerable component is gone."
    )
    assert "linux/arm/v6: grype failed, so fixed cannot be proven." in verdict.reason
    # the index is read once; each tool reads each platform's own manifest once
    scans = [
        (tool, f"registry:{child(n).reference}") for tool in ("grype", "syft") for n in PLATFORMS
    ]
    assert sorted(calls) == sorted([("crane", MULTI.reference), *scans])


def test_platforms_in_scope_limit_the_check_and_the_rest_are_named() -> None:
    (assessment,) = assess(FIX, scope(["linux/amd64"]), image_runner(answers()))
    verdict = assessment.verdict
    assert verdict.verdict is Verdict.FIXED
    assert [p.platform for p in verdict.platforms] == ["linux/amd64"]
    assert [(n.platform, n.reason) for n in verdict.not_checked] == [
        ("linux/arm64", "not in platforms"),
        ("linux/arm/v6", "not in platforms"),
    ]
    assert verdict.reason.endswith(
        "Not checked: linux/arm64 (not in platforms); linux/arm/v6 (not in platforms)."
    )


def test_an_image_whose_platforms_cannot_be_listed_is_unknown_and_not_scanned() -> None:
    calls: list[tuple[str, str]] = []
    unknown = ImageRef(
        registry="localhost:5001", repository=REPOSITORY, digest="sha256:" + "9" * 64
    )
    listed = ScopeFile.model_validate(
        {"schema_version": "1.0.0", "registries": ["localhost:5001"], "images": [unknown.reference]}
    )
    (assessment,) = assess(FIX, listed, counted(calls))
    assert assessment.verdict.verdict is Verdict.UNKNOWN
    assert assessment.verdict.reason == (
        "the image's platforms could not be listed: "
        "crane exited 1: MANIFEST_UNKNOWN: manifest unknown"
    )
    assert assessment.verdict.platforms == ()
    assert assessment.outcomes == ()
    assert [name for name, _ in calls] == ["crane"]


def test_the_bundle_records_each_platform_and_names_its_raw_files(tmp_path: Path) -> None:
    assessments = assess(FIX, scope(), image_runner(answers()))
    verdicts = [a.verdict for a in assessments]
    write_bundle(
        tmp_path,
        cve=CVE,
        fix_bytes=b"fix",
        scope_bytes=b"scope",
        assessments=assessments,
        vex=build_document(FIX, verdicts, author=AUTHOR, now=FINISH),
        cyclonedx=build_bom(FIX, verdicts, now=FINISH),
        started=START,
        finished=FINISH,
        kev=KEV,
    )
    bundle = json.loads((tmp_path / "bundle.json").read_text())
    assert schema_errors(build_validator(load_schema("bundle.schema.json")), bundle) == []
    (record,) = bundle["assets"]
    assert [(p["platform"], p["verdict"]) for p in record["platforms"]] == [
        ("linux/amd64", "fixed"),
        ("linux/arm64", "still_affected"),
        ("linux/arm/v6", "unknown"),
    ]
    arm64 = record["platforms"][1]
    assert arm64["scanned"]["grype"]["platform"] == "linux/arm64"
    assert record["platforms"][2]["scanned"]["sbom_version"]["platform"] == "linux/arm/v6"
    assert arm64["scanned"]["sbom_version"]["manifest_digest"] == CHILD["linux/arm64"]
    assert sorted(p.name for p in (tmp_path / "raw").iterdir()) == [
        "001-linux-amd64-grype.json",
        "001-linux-amd64-sbom_version.json",
        "001-linux-arm-v6-sbom_version.json",  # Grype failed on arm/v6: no output to keep
        "001-linux-arm64-grype.json",
        "001-linux-arm64-sbom_version.json",
    ]
    assert [r["raw_ref"] for r in arm64["results"]] == [
        "raw/001-linux-arm64-grype.json",
        "raw/001-linux-arm64-sbom_version.json",
    ]
    page = (tmp_path / "report.html").read_text()
    assert htmlreport.problems(page) == []
    assert "linux/amd64: fixed · linux/arm64: still_affected · linux/arm/v6: unknown" in page
    vex = json.loads((tmp_path / "openvex.json").read_text())
    (statement,) = vex["statements"]
    assert statement["status"] == "affected"
    assert statement["status_notes"] == record["reason"]


def test_the_summary_gives_each_platform_and_those_left_out() -> None:
    verdicts = [a.verdict for a in assess(FIX, scope(["linux/arm64"]), image_runner(answers()))]
    report = verify_summary(CVE, "out", verdicts, KEV).model_dump(mode="json")
    assert schema_errors(build_validator(load_schema("verify-summary.schema.json")), report) == []
    (line,) = report["assets"]
    assert line["platforms"] == [
        {"platform": "linux/arm64", "digest": CHILD["linux/arm64"], "verdict": "still_affected"}
    ]
    assert [n["platform"] for n in line["not_checked"]] == ["linux/amd64", "linux/arm/v6"]


def test_the_console_gives_each_platform_its_own_line() -> None:
    (assessment,) = assess(FIX, scope(["linux/amd64", "linux/arm64"]), image_runner(answers()))
    lines = _human(assessment.verdict).splitlines()
    pad = " " * 16
    assert lines[0] == f"{'still_affected':<15} {MULTI.reference}"
    assert lines[1] == f"{pad}2 platforms checked: linux/amd64 fixed, linux/arm64 still_affected."
    assert lines[2].startswith(f"{pad}linux/amd64: both methods agree the vulnerable component")
    assert lines[3].startswith(f"{pad}linux/arm64: both methods find the vulnerable component")
    assert lines[4] == f"{pad}Not checked: linux/arm/v6 (not in platforms)."


def test_the_gate_checks_every_platform_of_a_registry_image() -> None:
    closed = ClosedFile.model_validate(
        {
            "schema_version": "1.1.0",
            "registries": ["localhost:5001"],
            "platforms": ["linux/amd64", "linux/arm64"],
            "closed": [{"cve": CVE, "packages": FIX.model_dump()["packages"]}],
        }
    )
    calls: list[tuple[str, str]] = []
    result = run_gate(closed, MULTI.reference, _unavailable(), counted(calls))
    assert (
        schema_errors(
            build_validator(load_schema("gate-result.schema.json")), result.model_dump(mode="json")
        )
        == []
    )
    (line,) = result.results
    assert line.verdict is Verdict.STILL_AFFECTED
    assert [(p.platform, p.verdict) for p in line.platforms] == [
        ("linux/amd64", Verdict.FIXED),
        ("linux/arm64", Verdict.STILL_AFFECTED),
    ]
    assert [(p.platform, p.digest) for p in result.platforms] == [
        ("linux/amd64", CHILD["linux/amd64"]),
        ("linux/arm64", CHILD["linux/arm64"]),
    ]
    assert [(n.platform, n.reason) for n in result.not_checked] == [
        ("linux/arm/v6", "not in platforms")
    ]
    text = _gate_human(result).splitlines()
    assert text[0] == f"image {MULTI.reference}"
    assert text[1].startswith("  linux/amd64: grype: image ID ")
    assert text[2].startswith("  linux/arm64: grype: image ID ")
    assert text[3] == "  not checked: linux/arm/v6 (not in platforms)"
    assert ("grype", f"registry:{child('linux/arm/v6').reference}") not in calls


def _unavailable() -> Any:
    from fixproof import kev

    return kev.Unavailable("offline in this test")


def test_the_gate_bundle_keeps_each_platforms_output_under_its_name(tmp_path: Path) -> None:
    from fixproof.gate import write_gate_bundle

    closed = ClosedFile.model_validate(
        {
            "schema_version": "1.0.0",
            "registries": ["localhost:5001"],
            "closed": [{"cve": CVE, "packages": FIX.model_dump()["packages"]}],
        }
    )
    outcomes: list[Any] = []
    result = run_gate(closed, MULTI.reference, _unavailable(), image_runner(answers()), outcomes)
    record = write_gate_bundle(
        tmp_path / "out", result=result, outcomes=outcomes, closed_bytes=b"closed",
        started=START, finished=FINISH,
    )  # fmt: skip
    assert [r.path for r in record.raw] == [
        "raw/linux-amd64-grype.json",
        "raw/linux-amd64-sbom_version.json",
        "raw/linux-arm64-grype.json",
        "raw/linux-arm64-sbom_version.json",
        "raw/linux-arm-v6-sbom_version.json",  # Grype could not read arm/v6
    ]
    assert all((tmp_path / "out" / r.path).is_file() for r in record.raw)
