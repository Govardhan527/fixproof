"""The verdict rule's truth table (ADR-0007 item 1): every combination of method outcomes."""

import itertools

import pytest

from fixproof.model import (
    ImageAsset,
    ImageRef,
    Method,
    MethodResult,
    MethodStatus,
    Verdict,
    WorkloadAsset,
)
from fixproof.verdict import TABLE, combine, not_assessed

N, P, E = MethodStatus.NOT_PRESENT, MethodStatus.PRESENT, MethodStatus.ERROR
ASSET = ImageAsset(image=ImageRef.parse("localhost:5001/app@sha256:" + "ab" * 32))

# The accepted table, written out independently of the implementation.
EXPECTED = {
    (N, N): (Verdict.FIXED, "both methods agree the vulnerable component is gone"),
    (P, P): (Verdict.STILL_AFFECTED, "both methods find the vulnerable component"),
    (P, E): (Verdict.STILL_AFFECTED, "grype finds the vulnerable component; sbom_version failed"),
    (E, P): (Verdict.STILL_AFFECTED, "sbom_version finds the vulnerable component; grype failed"),
    (P, N): (Verdict.UNKNOWN, "the methods disagree"),
    (N, P): (Verdict.UNKNOWN, "the methods disagree"),
    (N, E): (Verdict.UNKNOWN, "sbom_version failed, so fixed cannot be proven"),
    (E, N): (Verdict.UNKNOWN, "grype failed, so fixed cannot be proven"),
    (E, E): (Verdict.UNKNOWN, "both methods failed"),
}


def result(method: Method, status: MethodStatus, asset: object = ASSET) -> MethodResult:
    return MethodResult.model_validate(
        {"asset": asset, "method": method, "status": status, "detail": f"{method} said {status}"}
    )


def test_the_table_covers_every_combination_exactly_once() -> None:
    combinations = set(itertools.product(MethodStatus, repeat=2))
    assert set(EXPECTED) == combinations
    assert set(TABLE) == combinations


@pytest.mark.parametrize(("grype", "sbom"), sorted(EXPECTED), ids=lambda s: str(s))
def test_truth_table(grype: MethodStatus, sbom: MethodStatus) -> None:
    verdict, summary = EXPECTED[(grype, sbom)]
    outcome = combine(ASSET, result(Method.GRYPE, grype), result(Method.SBOM_VERSION, sbom))
    assert outcome.verdict is verdict
    assert outcome.reason == (
        f"{summary}. grype: grype said {grype}. sbom_version: sbom_version said {sbom}."
    )
    assert [r.method for r in outcome.results] == [Method.GRYPE, Method.SBOM_VERSION]
    assert outcome.asset == ASSET


def test_fixed_needs_both_methods_to_say_not_present() -> None:
    for (grype, sbom), (verdict, _) in EXPECTED.items():
        assert (verdict is Verdict.FIXED) == (grype is N and sbom is N)


def test_still_affected_needs_presence_and_no_contradiction() -> None:
    for (grype, sbom), (verdict, _) in EXPECTED.items():
        statuses = {grype, sbom}
        assert (verdict is Verdict.STILL_AFFECTED) == (P in statuses and N not in statuses)


def test_results_must_belong_to_the_asset_and_come_from_each_method_once() -> None:
    other = ImageAsset(image=ImageRef.parse("localhost:5001/other@sha256:" + "cd" * 32))
    with pytest.raises(ValueError, match="another asset"):
        combine(ASSET, result(Method.GRYPE, N, other), result(Method.SBOM_VERSION, N))
    with pytest.raises(ValueError, match="expected the grype result first"):
        combine(ASSET, result(Method.SBOM_VERSION, N), result(Method.GRYPE, N))


def test_assets_that_were_not_assessed_are_unknown_with_the_reason() -> None:
    pod = WorkloadAsset(cluster="kind", namespace="demo", pod="p", container="c", image=None)
    outcome = not_assessed(pod, "image digest not resolved")
    assert (outcome.verdict, outcome.reason, outcome.results) == (
        Verdict.UNKNOWN,
        "image digest not resolved",
        (),
    )
