"""CycloneDX 1.6 VEX from asset verdicts (ADR-0012 item 5; SPEC_NOTES §4).

One `container` component per image digest, named by the same canonical purl as the OpenVEX
products, and one vulnerability entry per image. The verdict maps to `analysis.state` by the
spec's own definitions: fixed -> `resolved` ("has been remediated"), still_affected ->
`exploitable` ("may be directly or indirectly exploitable", with response `update`), unknown ->
`in_triage` ("is being investigated"). `not_affected` and `false_positive` are never written.
The serial number is derived from the content and the timestamp is the run's clock, so the same
verdicts always give the same document. It is validated against the official 1.6.2 schema.
"""

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.impact_analysis import ImpactAnalysisResponse, ImpactAnalysisState
from cyclonedx.model.vulnerability import BomTarget, Vulnerability, VulnerabilityAnalysis
from cyclonedx.output.json import JsonV1Dot6
from packageurl import PackageURL

from fixproof import __version__
from fixproof.inputs import FixFile
from fixproof.model import AssetVerdict, Verdict
from fixproof.validation import check_cyclonedx
from fixproof.vex import by_image

STATE: dict[Verdict, ImpactAnalysisState] = {
    Verdict.FIXED: ImpactAnalysisState.RESOLVED,
    Verdict.STILL_AFFECTED: ImpactAnalysisState.EXPLOITABLE,
    Verdict.UNKNOWN: ImpactAnalysisState.IN_TRIAGE,
}
_PLACEHOLDER = uuid.UUID(int=0)


class _CanonicalPurl(PackageURL):
    """A purl the library writes exactly as fixproof spells it (purl-spec v1.0.1, SPEC_NOTES §5).

    packageurl-python leaves `/` unencoded in qualifier values; the canonical form encodes it, as
    the OpenVEX products do. The library serialises a purl with `to_string()`.
    """

    canonical: str

    def to_string(self, encode: bool | None = True) -> str:
        return self.canonical


def _purl(canonical: str) -> _CanonicalPurl:
    purl = _CanonicalPurl.from_string(canonical)
    purl.canonical = canonical
    return purl


def _render(
    fix: FixFile, verdicts: Sequence[AssetVerdict], now: datetime, tool: str, serial: uuid.UUID
) -> str:
    tool_component = Component(type=ComponentType.APPLICATION, name="fixproof", version=tool)
    bom = Bom(serial_number=serial, metadata=BomMetaData(timestamp=now))
    bom.metadata.tools.components.add(tool_component)
    for index, (product, (image, verdict, reasons)) in enumerate(
        sorted(by_image(verdicts).items()), start=1
    ):
        name = image.repository.rsplit("/", 1)[-1]
        bom.components.add(
            Component(
                type=ComponentType.CONTAINER,
                name=name,
                version=image.digest,
                bom_ref=product,
                purl=_purl(product),
            )
        )
        responses = [ImpactAnalysisResponse.UPDATE] if verdict is Verdict.STILL_AFFECTED else None
        bom.vulnerabilities.add(
            Vulnerability(
                bom_ref=f"{fix.cve}-{index}",
                id=fix.cve,
                analysis=VulnerabilityAnalysis(
                    state=STATE[verdict], responses=responses, detail="; ".join(sorted(reasons))
                ),
                affects=[BomTarget(ref=product)],
            )
        )
    return JsonV1Dot6(bom).output_as_string()


def build_bom(
    fix: FixFile,
    verdicts: Sequence[AssetVerdict],
    *,
    now: datetime,
    tool_version: str = __version__,
) -> dict[str, Any]:
    """A validated CycloneDX 1.6 VEX document. Raises ValueError or OutputValidationError."""
    if not by_image(verdicts):
        raise ValueError("no verdict names an image digest, so there is nothing to state")
    draft = _render(fix, verdicts, now, tool_version, _PLACEHOLDER)
    digest = hashlib.sha256(draft.encode()).hexdigest()
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/Govardhan527/fixproof/{digest}")
    document: dict[str, Any] = json.loads(_render(fix, verdicts, now, tool_version, serial))
    check_cyclonedx(document)
    return document
