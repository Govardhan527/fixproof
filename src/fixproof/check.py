"""Checking one image on each of its platforms (ADR-0014), for `verify` and `gate`.

Each platform from `fixproof.platforms` gets both methods and the verdict rule; if the two tools
read different images (possible only for a local build, whose tag can move), that platform is
`unknown`. The image's verdict then comes from every platform (`verdict.combine_platforms`). An
image whose platforms could not be listed is `unknown` with the reason, and is not scanned.
"""

import dataclasses
from collections.abc import Sequence
from dataclasses import dataclass

from fixproof.bundle import Assessment
from fixproof.inputs import FixFile
from fixproof.methods import MethodOutcome, grype, sbom_version
from fixproof.model import Asset, AssetVerdict, PlatformVerdict, Verdict
from fixproof.platforms import Plan, Target
from fixproof.tools import Runner
from fixproof.verdict import combine, combine_platforms


@dataclass(frozen=True)
class PlatformCheck:
    """One platform's verdict and the method outcomes behind it."""

    verdict: PlatformVerdict
    outcomes: tuple[MethodOutcome, ...]


def different_images(outcomes: Sequence[MethodOutcome]) -> str | None:
    """Why the tools' reads cannot be trusted together, or None if they read one image."""
    ids = {o.scanned["image_id"] for o in outcomes if o.scanned.get("image_id")}
    if len(ids) > 1:
        return f"the two tools read different images ({', '.join(sorted(ids))})"
    return None


def _scanned(outcomes: Sequence[MethodOutcome], key: str) -> str:
    return next((o.scanned[key] for o in outcomes if o.scanned.get(key)), "")


def check_platform(asset: Asset, target: Target, fix: FixFile, run: Runner) -> PlatformCheck:
    """Both methods and the verdict rule on one platform of `asset`."""
    by_grype = grype.assess(asset, fix.cve, run, target)
    by_sbom = sbom_version.assess(asset, fix, run, target)
    both = (by_grype, by_sbom)
    combined = combine(asset, by_grype.result, by_sbom.result)
    verdict, reason = combined.verdict, combined.reason
    mismatch = different_images(both)
    if mismatch is not None:
        verdict, reason = Verdict.UNKNOWN, mismatch
    platform = target.platform or _scanned(both, "platform") or "unknown platform"
    digest = target.image.digest if target.image else _scanned(both, "manifest_digest")
    outcomes = tuple(dataclasses.replace(o, platform=platform, digest=digest) for o in both)
    return PlatformCheck(
        PlatformVerdict(
            platform=platform,
            digest=digest,
            verdict=verdict,
            reason=reason,
            results=combined.results,
        ),
        outcomes,
    )


def finish(asset: Asset, plan: Plan, checks: Sequence[PlatformCheck]) -> Assessment:
    """The image's assessment from its plan and the checks of its platforms."""
    if plan.problem is not None:
        verdict = AssetVerdict(
            asset=asset,
            verdict=Verdict.UNKNOWN,
            reason=plan.problem,
            not_checked=plan.not_checked,
        )
        return Assessment(verdict)
    combined = combine_platforms(asset, [c.verdict for c in checks], plan.not_checked)
    return Assessment(combined, tuple(o for c in checks for o in c.outcomes))
