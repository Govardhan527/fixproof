"""The `verify --json` summary (ADR-0007 Amendment 1): format `verify-summary`, 1.3.0."""

from collections.abc import Sequence
from typing import Literal

from pydantic import Field

from fixproof.bundle import Summary, summarise
from fixproof.kev import Kev
from fixproof.model import (
    AssetVerdict,
    Contract,
    CveId,
    NotChecked,
    Text,
    Verdict,
    WorkloadAsset,
)

# 1.1.0: `workload`, `owner`; 1.2.0: `kev`; 1.3.0: `platforms`, `not_checked` (ADR-0014)
SUMMARY_VERSION: Literal["1.3.0"] = "1.3.0"


class PlatformLine(Contract):
    platform: Text
    digest: str
    verdict: Verdict


class AssetLine(Contract):
    asset: str | None  # the image reference; None for an asset with no resolved image
    verdict: Verdict
    reason: Text
    workload: Text | None = Field(
        default=None, description="cluster/namespace/pod/container, for a running workload."
    )
    owner: Text | None = Field(
        default=None, description="The pod's controller, e.g. Deployment/api."
    )
    platforms: tuple[PlatformLine, ...] = Field(
        default=(), description="The verdict on each platform checked (ADR-0014)."
    )
    not_checked: tuple[NotChecked, ...] = Field(
        default=(), description="Platforms of the image index that were not checked, and why."
    )


class VerifySummary(Contract):
    schema_version: Literal["1.3.0"]
    cve: CveId
    out: Text
    summary: Summary
    kev: Kev
    assets: tuple[AssetLine, ...]


def _line(item: AssetVerdict) -> AssetLine:
    asset = item.asset
    workload = asset if isinstance(asset, WorkloadAsset) else None
    return AssetLine(
        asset=asset.image.reference if asset.image else None,
        verdict=item.verdict,
        reason=item.reason,
        workload=workload.location if workload else None,
        owner=workload.owner if workload else None,
        platforms=tuple(
            PlatformLine(platform=p.platform, digest=p.digest, verdict=p.verdict)
            for p in item.platforms
        ),
        not_checked=item.not_checked,
    )


def verify_summary(cve: str, out: str, verdicts: Sequence[AssetVerdict], kev: Kev) -> VerifySummary:
    return VerifySummary(
        schema_version=SUMMARY_VERSION,
        cve=cve,
        out=out,
        summary=summarise(verdicts),
        kev=kev,
        assets=tuple(_line(item) for item in verdicts),
    )
