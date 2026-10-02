"""The verdict rule (ADR-0007 item 1), the core of fixproof.

`fixed` needs both methods to say the vulnerable component is not present. `still_affected`
needs one method to find it and the other not to contradict it. A disagreement or a failure is
`unknown`, with both methods' details in the reason; it is never collapsed into `fixed`.
"""

from fixproof.model import Asset, AssetVerdict, Method, MethodResult, MethodStatus, Verdict

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
