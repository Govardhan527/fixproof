"""The two evidence methods against trimmed real tool output (tests/tool_outputs.py)."""

import json
from typing import Any

import pytest

from fixproof.methods import grype, sbom_version
from fixproof.model import BuildAsset, Method, MethodStatus, WorkloadAsset
from fixproof.tools import ToolRun
from tool_outputs import (
    ASSET,
    CVE,
    DIGEST,
    MARKER,
    edited,
    output,
    requests_fix,
    runner,
)

GRYPE_VULNERABLE, GRYPE_FIXED = output("grype", "vulnerable"), output("grype", "fixed")
SYFT_VULNERABLE, SYFT_FIXED = output("syft", "vulnerable"), output("syft", "fixed")
FIX = requests_fix()


# --- grype ---------------------------------------------------------------------------------


def test_grype_finds_the_cve_through_the_related_ids() -> None:
    calls: list[tuple[str, list[str], dict[str, str]]] = []
    result = grype.assess(ASSET, CVE, runner({"grype": GRYPE_VULNERABLE}, calls))
    assert result.result.method is Method.GRYPE
    assert result.result.status is MethodStatus.PRESENT
    assert result.result.detail == (f"{CVE}: pkg:pypi/requests@2.30.0 matches GHSA-j8r2-6x86-q33q")
    assert calls == [
        (
            "grype",
            [f"registry:localhost:5001/fixproof/demo-app@{DIGEST}", "-o", "json"],
            grype.ENV,
        )
    ]


def test_grype_on_the_fixed_image() -> None:
    result = grype.assess(ASSET, CVE, runner({"grype": GRYPE_FIXED}))
    assert result.result.status is MethodStatus.NOT_PRESENT
    assert result.result.detail == f"no match for {CVE} among 3 matches"
    assert result.tool == {
        "name": "grype",
        "version": "0.119.0",
        "db": {
            "schemaVersion": "v6.1.9",
            "built": "2026-10-02T06:31:53Z",
            "from": GRYPE_FIXED["descriptor"]["db"]["status"]["from"],
        },
    }
    assert result.scanned["platform"] == "linux/amd64"


def test_grype_matches_a_cve_reported_as_the_primary_id() -> None:
    def as_cve(doc: dict[str, Any]) -> None:
        doc["matches"][0]["vulnerability"]["id"] = CVE
        doc["matches"][0]["relatedVulnerabilities"] = []

    result = grype.assess(ASSET, CVE, runner({"grype": edited(GRYPE_VULNERABLE, as_cve)}))
    assert result.result.status is MethodStatus.PRESENT


@pytest.mark.parametrize(
    ("answer", "detail"),
    [
        (ToolRun(None, b"", "", "grype not found on PATH"), "grype not found on PATH"),
        (ToolRun(1, b"", "x\nERROR db is too old\n"), "grype exited 1: ERROR db is too old"),
        (ToolRun(0, b"not json", ""), "grype output is not JSON"),
        (ToolRun(0, b"[]", ""), "grype output is not a JSON object"),
        (ToolRun(0, b"{}", ""), "grype output has an unexpected shape (KeyError('descriptor'))"),
    ],
)
def test_grype_failures_are_errors(answer: ToolRun, detail: str) -> None:
    result = grype.assess(ASSET, CVE, runner({"grype": answer}))
    assert (result.result.status, result.result.detail, result.raw) == (
        MethodStatus.ERROR,
        detail,
        None,
    )


@pytest.mark.parametrize(
    ("edit", "detail"),
    [
        (lambda d: d["descriptor"].update(name="other"), "the output is not from grype"),
        (
            lambda d: d["descriptor"]["db"]["status"].update(schemaVersion="v5.0.1"),
            "grype DB schema 'v5.0.1' is not v6",
        ),
        (
            lambda d: d["source"]["target"].update(repoDigests=[]),
            "grype scanned sha256:56272f4e41045942ef0e5255b87e13d401d88990d592065667d44e184d63d4e7"
            f", not {DIGEST}",
        ),
        (lambda d: d["source"].update(target="dir"), "grype did not report an image source"),
    ],
)
def test_grype_output_that_cannot_be_trusted_is_an_error(edit: Any, detail: str) -> None:
    result = grype.assess(ASSET, CVE, runner({"grype": edited(GRYPE_VULNERABLE, edit)}))
    assert (result.result.status, result.result.detail) == (MethodStatus.ERROR, detail)


def test_grype_accepts_the_digest_as_the_manifest_digest() -> None:
    def single_platform(doc: dict[str, Any]) -> None:
        doc["source"]["target"].update(manifestDigest=DIGEST, repoDigests=[])

    result = grype.assess(ASSET, CVE, runner({"grype": edited(GRYPE_FIXED, single_platform)}))
    assert result.result.status is MethodStatus.NOT_PRESENT


# --- sbom_version ----------------------------------------------------------------------------


def test_sbom_finds_a_copy_below_the_fix() -> None:
    calls: list[tuple[str, list[str], dict[str, str]]] = []
    result = sbom_version.assess(ASSET, FIX, runner({"syft": SYFT_VULNERABLE}, calls))
    assert result.result.method is Method.SBOM_VERSION
    assert result.result.status is MethodStatus.PRESENT
    assert result.result.detail == (
        "requests 2.30.0 at /usr/local/lib/python3.12/site-packages"
        "/requests-2.30.0.dist-info/METADATA is below the fix (2.31.0)"
    )
    assert calls[0][2] == sbom_version.ENV
    assert result.tool == {"name": "syft", "version": "1.54.0", "schema": "16.1.11"}


def test_sbom_on_the_fixed_image() -> None:
    result = sbom_version.assess(ASSET, FIX, runner({"syft": SYFT_FIXED}))
    assert result.result.status is MethodStatus.NOT_PRESENT
    assert result.result.detail.endswith("requests-2.31.0.dist-info/METADATA is fixed")


def test_sbom_any_unfixed_copy_counts() -> None:
    def two_copies(doc: dict[str, Any]) -> None:
        doc["artifacts"].append(SYFT_VULNERABLE["artifacts"][0])

    result = sbom_version.assess(ASSET, FIX, runner({"syft": edited(SYFT_FIXED, two_copies)}))
    assert result.result.status is MethodStatus.PRESENT
    assert "2.30.0" in result.result.detail


def test_sbom_absent_package_is_not_present() -> None:
    fix = requests_fix(name="urllib3", fixed_version="2.0.0")
    result = sbom_version.assess(ASSET, fix, runner({"syft": SYFT_VULNERABLE}))
    assert (result.result.status, result.result.detail) == (
        MethodStatus.NOT_PRESENT,
        "no urllib3 package among 1 packages",
    )


def test_sbom_backport_range_counts_as_fixed() -> None:
    fix = requests_fix(fixed_vers="vers:pypi/>=2.30.0|<2.31")
    result = sbom_version.assess(ASSET, fix, runner({"syft": SYFT_VULNERABLE}))
    assert result.result.status is MethodStatus.NOT_PRESENT


@pytest.mark.parametrize(
    ("edit", "detail"),
    [
        (lambda d: d["artifacts"][0].update(version="not.a.version!"), "is not a PEP 440 version"),
        (lambda d: d["artifacts"][0].update(purl=""), "requests 2.30.0 has no usable purl"),
        (lambda d: d["schema"].update(version="17.0.0"), "syft JSON schema '17.0.0' is not 16.x"),
        (lambda d: d["descriptor"].update(name="other"), "the output is not from syft"),
        (lambda d: d["source"]["metadata"].update(repoDigests=["x@sha256:00"]), "not sha256:"),
        (lambda d: d.pop("artifacts"), "unexpected shape (KeyError('artifacts'))"),
    ],
)
def test_sbom_output_that_cannot_be_used_is_an_error(edit: Any, detail: str) -> None:
    result = sbom_version.assess(ASSET, FIX, runner({"syft": edited(SYFT_VULNERABLE, edit)}))
    assert result.result.status is MethodStatus.ERROR
    assert detail in result.result.detail


def test_sbom_compares_debian_versions() -> None:
    fix = requests_fix(ecosystem="deb", namespace="debian", name="libdemo1", fixed_version="1.0-1")

    def add_deb(version: str) -> Any:
        def edit(doc: dict[str, Any]) -> None:
            doc["artifacts"].append(
                {
                    **doc["artifacts"][0],
                    "name": "libdemo1",
                    "version": version,
                    "purl": f"pkg:deb/debian/libdemo1@{version}?arch=amd64",
                }
            )

        return edit

    below = sbom_version.assess(
        ASSET, fix, runner({"syft": edited(SYFT_VULNERABLE, add_deb("1.0~rc1-1"))})
    )
    assert below.result.status is MethodStatus.PRESENT
    assert "libdemo1 1.0~rc1-1" in below.result.detail
    at = sbom_version.assess(
        ASSET, fix, runner({"syft": edited(SYFT_VULNERABLE, add_deb("1:0.5-1"))})
    )
    assert at.result.status is MethodStatus.NOT_PRESENT  # the epoch outranks the version


def test_unrelated_artifacts_without_a_purl_are_ignored() -> None:
    def add_other(doc: dict[str, Any]) -> None:
        doc["artifacts"].append({"name": "busybox", "version": "1.36", "purl": ""})

    result = sbom_version.assess(ASSET, FIX, runner({"syft": edited(SYFT_FIXED, add_other)}))
    assert result.result.status is MethodStatus.NOT_PRESENT


# --- both ------------------------------------------------------------------------------------


@pytest.mark.parametrize("assess", [grype.assess, sbom_version.assess])
def test_methods_need_an_image(assess: Any) -> None:
    pod = WorkloadAsset(cluster="kind", namespace="demo", pod="p", container="c", image=None)
    with pytest.raises(ValueError, match="need an asset with an image digest"):
        assess(pod, CVE if assess is grype.assess else FIX)


def test_stored_output_never_holds_image_config_files_or_tool_configuration() -> None:
    for result in (
        grype.assess(ASSET, CVE, runner({"grype": GRYPE_VULNERABLE})),
        sbom_version.assess(ASSET, FIX, runner({"syft": SYFT_VULNERABLE})),
    ):
        stored = json.dumps(result.raw)
        assert MARKER not in stored
        assert "bWFya2Vy" not in stored  # the planted file contents
        assert '"configuration"' not in stored
        assert "vulnerability.db" not in stored  # Grype's local DB file (SPEC_NOTES §17)
        assert '"labels"' not in stored
        assert result.raw is not None
        assert "files" not in result.raw  # Syft's file listing; package metadata may list files


@pytest.mark.parametrize("source", ["docker:app:ci", "oci-archive:build/app.tar"])
def test_a_local_build_is_read_from_its_source_with_no_digest_to_match(source: str) -> None:
    """ADR-0012 item 2: the tools read the build where it is; what they read is recorded."""
    build = BuildAsset(source=source)
    calls: list[tuple[str, list[str], dict[str, str]]] = []
    documents = {"grype": GRYPE_VULNERABLE, "syft": SYFT_VULNERABLE}
    by_grype = grype.assess(build, CVE, runner(documents, calls))
    by_sbom = sbom_version.assess(build, FIX, runner(documents, calls))
    assert [call[1][0] for call in calls] == [source, source]
    assert (by_grype.result.status, by_sbom.result.status) == (
        MethodStatus.PRESENT,
        MethodStatus.PRESENT,
    )
    image_id = GRYPE_VULNERABLE["source"]["target"]["imageID"]
    assert image_id.startswith("sha256:")
    assert by_grype.scanned["image_id"] == image_id
    assert by_sbom.scanned["image_id"] == SYFT_VULNERABLE["source"]["metadata"]["imageID"]
