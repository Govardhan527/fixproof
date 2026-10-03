"""OpenVEX documents from asset verdicts (ADR-0005 item 4; SPEC_NOTES §1 and §14).

One statement per image digest. The verdict maps to a status by OQ-2: fixed -> `fixed`,
still_affected -> `affected` (with the required `action_statement`), unknown ->
`under_investigation`. Nothing here can produce `not_affected`. Every document is validated
against the official schema, formats included, before it is returned or written.
"""

import hashlib
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from fixproof import __version__
from fixproof.canonical import iso, to_json
from fixproof.inputs import FixFile
from fixproof.model import AssetVerdict, ImageRef, Verdict
from fixproof.purl import build
from fixproof.validation import check_openvex

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"  # OQ-1
DEFAULT_ID_PREFIX = "https://openvex.dev/docs/fixproof/"  # OpenVEX shared namespace (§1)
STATUS: dict[Verdict, str] = {
    Verdict.FIXED: "fixed",
    Verdict.STILL_AFFECTED: "affected",
    Verdict.UNKNOWN: "under_investigation",
}


def image_purl(image: ImageRef) -> str:
    """The canonical OCI purl for an image (purl oci type, SPEC_NOTES §5)."""
    name = image.repository.rsplit("/", 1)[-1]
    repository_url = f"{image.registry}/{image.repository}"
    return build("oci", name, version=image.digest, qualifiers={"repository_url": repository_url})


def action_statement(fix: FixFile) -> str:
    """What to do about an affected image: reach a fixed version of every listed package."""
    steps = []
    for package in fix.packages:
        step = f"Upgrade {package.purl} to {package.fixed_version} or later"
        if package.fixed_vers:
            step += f", or to a version in {package.fixed_vers}"
        steps.append(step)
    return "; ".join(steps) + "."


def by_image(verdicts: Sequence[AssetVerdict]) -> dict[str, tuple[ImageRef, Verdict, set[str]]]:
    """One verdict per image digest, keyed by its purl, with every reason given for it.

    Workloads share their image's verdict; an asset with no resolved image has no product and
    is left out (it stays in the report). Raises ValueError if one image has two verdicts.
    """
    found: dict[str, tuple[ImageRef, Verdict, set[str]]] = {}
    for item in verdicts:
        if item.asset.image is None:
            continue
        product = image_purl(item.asset.image)
        _, verdict, reasons = found.setdefault(product, (item.asset.image, item.verdict, set()))
        if verdict != item.verdict:
            raise ValueError(
                f"{product} has two verdicts ({verdict}, {item.verdict}); "
                "verdicts are per image and must agree"
            )
        reasons.add(item.reason)
    return found


def _statements(fix: FixFile, verdicts: Sequence[AssetVerdict]) -> list[dict[str, Any]]:

    subcomponents = [
        {"@id": purl, "identifiers": {"purl": purl}}
        for purl in sorted(package.purl for package in fix.packages)
    ]
    statements = []
    for product, (_, verdict, reasons) in sorted(by_image(verdicts).items()):
        statement: dict[str, Any] = {
            "vulnerability": {"name": fix.cve},
            "products": [
                {"@id": product, "identifiers": {"purl": product}, "subcomponents": subcomponents}
            ],
            "status": STATUS[verdict],
            "status_notes": "; ".join(sorted(reasons)),
        }
        if verdict is Verdict.STILL_AFFECTED:
            statement["action_statement"] = action_statement(fix)
        statements.append(statement)
    return statements


def build_document(
    fix: FixFile,
    verdicts: Sequence[AssetVerdict],
    *,
    author: str,
    now: datetime,
    id_prefix: str = DEFAULT_ID_PREFIX,
    tool_version: str = __version__,
) -> dict[str, Any]:
    """Return a validated OpenVEX document. Raises ValueError or OutputValidationError."""
    if not author.strip():
        raise ValueError("an OpenVEX document needs a non-empty author")
    statements = _statements(fix, verdicts)
    if not statements:
        raise ValueError("no verdict names an image digest, so there is nothing to state")
    body: dict[str, Any] = {
        "@context": OPENVEX_CONTEXT,
        "author": author,
        "statements": statements,
        "timestamp": iso(now),
        "tooling": f"fixproof {tool_version}",
        "version": 1,
    }
    digest = hashlib.sha256(to_json(body)).hexdigest()
    document = {"@id": f"{id_prefix}vex-{digest[:32]}", **body}
    check_openvex(document)
    return document


def write_document(path: Path, document: dict[str, Any]) -> None:
    """Validate `document` again and write it in canonical form."""
    check_openvex(document)
    path.write_bytes(to_json(document))
