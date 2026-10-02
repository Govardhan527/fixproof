"""The `verify --json` summary (ADR-0007 Amendment 1): format `verify-summary`, 1.0.0."""

from collections.abc import Sequence
from typing import Literal

from fixproof.bundle import Summary, summarise
from fixproof.model import AssetVerdict, Contract, CveId, Text, Verdict

SUMMARY_VERSION: Literal["1.0.0"] = "1.0.0"


class AssetLine(Contract):
    asset: str | None  # the image reference; None for an asset with no resolved image
    verdict: Verdict
    reason: Text


class VerifySummary(Contract):
    schema_version: Literal["1.0.0"]
    cve: CveId
    out: Text
    summary: Summary
    assets: tuple[AssetLine, ...]


def verify_summary(cve: str, out: str, verdicts: Sequence[AssetVerdict]) -> VerifySummary:
    return VerifySummary(
        schema_version=SUMMARY_VERSION,
        cve=cve,
        out=out,
        summary=summarise(verdicts),
        assets=tuple(
            AssetLine(
                asset=item.asset.image.reference if item.asset.image else None,
                verdict=item.verdict,
                reason=item.reason,
            )
            for item in verdicts
        ),
    )
