"""Method `grype`: does Grype match the CVE in the image? (ADR-0007 item 3)

Grype scans the image itself by digest. A match counts when the CVE is the match's own id or one
of its related ids: PyPI matches carry the GHSA id with the CVE only among the related ones
(SPEC_NOTES §17). Updates and update checks are off, and the DB age check stays on, so a stale
DB is an error.
"""

from typing import Any

from fixproof import sanitize
from fixproof.methods import MethodOutcome, Unusable, outcome, parse_output, scanned_image, target
from fixproof.model import Asset, Method, MethodStatus
from fixproof.platforms import Target
from fixproof.tools import Runner, run_tool

ENV = {
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    "GRYPE_DB_AUTO_UPDATE": "false",
    "GRYPE_DB_VALIDATE_AGE": "true",
}
DB_SCHEMA_MAJOR = "v6."


def _ids(match: dict[str, Any]) -> set[str]:
    related = match.get("relatedVulnerabilities") or []
    return {match["vulnerability"]["id"], *(item["id"] for item in related)}


def _package(match: dict[str, Any]) -> str:
    artifact = match["artifact"]
    return str(artifact.get("purl") or f"{artifact['name']} {artifact['version']}")


def assess(
    asset: Asset, cve: str, run: Runner = run_tool, platform: Target | None = None
) -> MethodOutcome:
    argument, image = target(asset, platform)
    try:
        document = parse_output("grype", run("grype", [argument, "-o", "json"], ENV))
        descriptor = document["descriptor"]
        if descriptor.get("name") != "grype":
            raise Unusable("the output is not from grype")
        status = descriptor.get("db", {}).get("status", {})
        tool = {
            "name": "grype",
            "version": descriptor.get("version"),
            "db": {key: status.get(key) for key in ("schemaVersion", "built", "from")},
        }
        if not str(status.get("schemaVersion", "")).startswith(DB_SCHEMA_MAJOR):
            raise Unusable(f"grype DB schema {status.get('schemaVersion')!r} is not v6")
        scanned = scanned_image("grype", document["source"].get("target"), image)
        hits = sorted(
            {
                f"{_package(m)} matches {m['vulnerability']['id']}"
                for m in document["matches"]
                if cve in _ids(m)
            }
        )
    except Unusable as exc:
        return outcome(asset, Method.GRYPE, MethodStatus.ERROR, str(exc))
    except (KeyError, TypeError, AttributeError) as exc:
        return outcome(
            asset,
            Method.GRYPE,
            MethodStatus.ERROR,
            f"grype output has an unexpected shape ({exc!r})",
        )

    extra: dict[str, Any] = {"raw": sanitize.grype(document), "tool": tool, "scanned": scanned}
    if hits:
        return outcome(
            asset, Method.GRYPE, MethodStatus.PRESENT, f"{cve}: " + "; ".join(hits), **extra
        )
    detail = f"no match for {cve} among {len(document['matches'])} matches"
    return outcome(asset, Method.GRYPE, MethodStatus.NOT_PRESENT, detail, **extra)
