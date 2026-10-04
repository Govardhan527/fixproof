"""The verdict rule (ADR-0007 item 1), the core of fixproof.

`fixed` needs both methods to say the vulnerable component is not present. `still_affected`
needs one method to find it and the other not to contradict it. A disagreement or a failure is
`unknown`, with both methods' details in the reason; it is never collapsed into `fixed`.

An image with several platforms gets the rule on each, then one verdict (ADR-0014 item 3): any
`still_affected` platform makes it `still_affected`, every platform `fixed` makes it `fixed`,
and anything else is `unknown`.
"""

from collections.abc import Sequence

from fixproof.model import (
    Asset,
    AssetVerdict,
    Method,
    MethodResult,
    MethodStatus,
    NotChecked,
    PlatformVerdict,
    Verdict,
)

N, P, E = MethodStatus.NOT_PRESENT, MethodStatus.PRESENT, MethodStatus.ERROR

# (grype, sbom_version) -> (verdict, summary). Every combination appears exactly once.
TABLE: dict[tuple[MethodStatus, MethodStatus], tuple[Verdict, str]] = {
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


def combine(asset: Asset, grype: MethodResult, sbom: MethodResult) -> AssetVerdict:
    """Combine the two method results for one asset into its verdict."""
    if (grype.method, sbom.method) != (Method.GRYPE, Method.SBOM_VERSION):
        raise ValueError("expected the grype result first and the sbom_version result second")
    if grype.asset != asset or sbom.asset != asset:
        raise ValueError("a method result belongs to another asset")
    verdict, summary = TABLE[(grype.status, sbom.status)]
    reason = f"{summary}. grype: {grype.detail}. sbom_version: {sbom.detail}."
    return AssetVerdict(asset=asset, verdict=verdict, reason=reason, results=(grype, sbom))


def across_platforms(verdicts: Sequence[Verdict]) -> Verdict:
    """One verdict for an image from its platforms' verdicts (ADR-0014 item 3)."""
    if not verdicts:
        raise ValueError("an image needs at least one checked platform")
    if Verdict.STILL_AFFECTED in verdicts:
        return Verdict.STILL_AFFECTED
    return Verdict.FIXED if set(verdicts) == {Verdict.FIXED} else Verdict.UNKNOWN


def platform_lines(
    platforms: Sequence[PlatformVerdict], not_checked: Sequence[NotChecked] = ()
) -> list[str]:
    """The reason of an image with several platforms, or some left out, one line per part:
    each platform's verdict, then each platform's reason, then the platforms not checked."""
    count = f"{len(platforms)} platform{'s' if len(platforms) != 1 else ''} checked"
    each = ", ".join(f"{p.platform} {p.verdict.value}" for p in platforms)
    lines = [f"{count}: {each}.", *(f"{p.platform}: {p.reason}" for p in platforms)]
    if not_checked:
        lines.append(
            "Not checked: " + "; ".join(f"{n.platform} ({n.reason})" for n in not_checked) + "."
        )
    return lines


def combine_platforms(
    asset: Asset, platforms: Sequence[PlatformVerdict], not_checked: Sequence[NotChecked] = ()
) -> AssetVerdict:
    """The image's verdict from every checked platform, naming those left out.

    With one platform and nothing left out, the reason is that platform's reason unchanged.
    """
    verdict = across_platforms([p.verdict for p in platforms])
    if len(platforms) == 1 and not not_checked:
        reason = platforms[0].reason
    else:
        reason = " ".join(platform_lines(platforms, not_checked))
    return AssetVerdict(
        asset=asset,
        verdict=verdict,
        reason=reason,
        results=tuple(r for p in platforms for r in p.results),
        platforms=tuple(platforms),
        not_checked=tuple(not_checked),
    )
