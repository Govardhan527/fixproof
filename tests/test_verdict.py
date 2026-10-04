"""The verdict rule's truth table (ADR-0007 item 1): every combination of method outcomes; and
the rule across an image's platforms (ADR-0014 item 3): every combination of up to four."""

import itertools

import pytest

from fixproof.model import (
    ImageAsset,
    ImageRef,
    Method,
    MethodResult,
    MethodStatus,
    NotChecked,
    PlatformVerdict,
    Verdict,
)
from fixproof.verdict import TABLE, across_platforms, combine, combine_platforms

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


F, A, U = Verdict.FIXED, Verdict.STILL_AFFECTED, Verdict.UNKNOWN
EVERY_MIX = [mix for size in range(1, 5) for mix in itertools.product((F, A, U), repeat=size)]


def expected_across(mix: tuple[Verdict, ...]) -> Verdict:
    """ADR-0014 item 3, written out independently of the implementation."""
    if any(v is A for v in mix):
        return A
    if all(v is F for v in mix):
        return F
    return U


@pytest.mark.parametrize("mix", EVERY_MIX, ids=lambda mix: "-".join(v.value for v in mix))
def test_every_mix_of_platform_verdicts(mix: tuple[Verdict, ...]) -> None:
    assert across_platforms(mix) is expected_across(mix)


def test_unknown_on_one_platform_is_never_outweighed_by_fixed_on_others() -> None:
    assert all(across_platforms(mix) is not F for mix in EVERY_MIX if U in mix)
    assert all(across_platforms(mix) is A for mix in EVERY_MIX if A in mix)


def test_an_image_needs_a_checked_platform() -> None:
    with pytest.raises(ValueError, match="at least one checked platform"):
        across_platforms([])


def platform(name: str, verdict: Verdict) -> PlatformVerdict:
    results = (result(Method.GRYPE, N), result(Method.SBOM_VERSION, N))
    return PlatformVerdict(
        platform=name, digest="sha256:" + "0" * 64, verdict=verdict, reason=f"{name} reason.",
        results=results,
    )  # fmt: skip


def test_one_platform_with_nothing_left_out_keeps_its_reason_unchanged() -> None:
    combined = combine_platforms(ASSET, [platform("linux/amd64", F)])
    assert (combined.verdict, combined.reason) == (F, "linux/amd64 reason.")
    assert len(combined.results) == 2
    assert combined.not_checked == ()


def test_several_platforms_give_each_verdict_then_each_reason_then_those_left_out() -> None:
    left = NotChecked(platform="windows/amd64", digest="sha256:" + "1" * 64, reason="Linux only")
    combined = combine_platforms(
        ASSET, [platform("linux/amd64", F), platform("linux/arm64", A)], [left]
    )
    assert combined.verdict is A
    assert combined.reason == (
        "2 platforms checked: linux/amd64 fixed, linux/arm64 still_affected. "
        "linux/amd64: linux/amd64 reason. linux/arm64: linux/arm64 reason. "
        "Not checked: windows/amd64 (Linux only)."
    )
    assert [p.platform for p in combined.platforms] == ["linux/amd64", "linux/arm64"]
    assert len(combined.results) == 4
    assert combined.not_checked == (left,)


def test_one_platform_with_others_left_out_says_so() -> None:
    left = NotChecked(
        platform="linux/arm64", digest="sha256:" + "1" * 64, reason="not in platforms"
    )
    combined = combine_platforms(ASSET, [platform("linux/amd64", F)], [left])
    assert combined.reason == (
        "1 platform checked: linux/amd64 fixed. linux/amd64: linux/amd64 reason. "
        "Not checked: linux/arm64 (not in platforms)."
    )
