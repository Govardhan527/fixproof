"""Method `sbom_version`: is any copy of a fixed package below the fix? (ADR-0007 item 4)

Syft lists the image's packages. Each package named in `fix.yaml` is found by purl type,
namespace and name, and every copy's version is compared with the fix. A version fixproof cannot
compare (an invalid version, or an ecosystem without a comparator yet) is an error, never a pass.
"""

from typing import Any

from fixproof import sanitize
from fixproof.inputs import FixFile, FixPackage
from fixproof.methods import MethodOutcome, Unusable, outcome, parse_output, scanned_image, target
from fixproof.model import Asset, Method, MethodStatus
from fixproof.purl import identity
from fixproof.tools import Runner, run_tool
from fixproof.versions import VersionError, is_fixed

ENV = {"SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_FILE_METADATA_SELECTION": "none"}
SCHEMA_MAJOR = "16."


def _copies(package: FixPackage, artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every artifact that is this package. An unidentifiable namesake is an error."""
    wanted = identity(package.purl)
    found = []
    for artifact in artifacts:
        try:
            ident = identity(artifact.get("purl") or "")
        except ValueError:
            if str(artifact.get("name", "")).lower() == package.name.lower():
                raise Unusable(
                    f"{artifact['name']} {artifact.get('version')} has no usable purl"
                ) from None
            continue
        if (ident.type, ident.namespace, ident.name) == (
            wanted.type,
            wanted.namespace,
            wanted.name,
        ):
            found.append(artifact)
    return found


def _where(artifact: dict[str, Any]) -> str:
    locations = artifact.get("locations") or [{}]
    return str(locations[0].get("path", "?"))


def assess(asset: Asset, fix: FixFile, run: Runner = run_tool) -> MethodOutcome:
    argument, image = target(asset)
    try:
        document = parse_output("syft", run("syft", [argument, "-o", "json"], ENV))
        descriptor, schema = document["descriptor"], document["schema"]
        if descriptor.get("name") != "syft":
            raise Unusable("the output is not from syft")
        tool = {
            "name": "syft",
            "version": descriptor.get("version"),
            "schema": schema.get("version"),
        }
        if not str(schema.get("version", "")).startswith(SCHEMA_MAJOR):
            raise Unusable(f"syft JSON schema {schema.get('version')!r} is not 16.x")
        scanned = scanned_image("syft", document["source"].get("metadata"), image)
        artifacts = document["artifacts"]
        unfixed, fixed = [], []
        for package in fix.packages:
            for artifact in _copies(package, artifacts):
                line = f"{artifact['name']} {artifact['version']} at {_where(artifact)}"
                if is_fixed(package, artifact["version"]):
                    fixed.append(f"{line} is fixed")
                else:
                    unfixed.append(f"{line} is below the fix ({package.fixed_version})")
    except (Unusable, VersionError) as exc:
        return outcome(asset, Method.SBOM_VERSION, MethodStatus.ERROR, str(exc))
    except (KeyError, TypeError, AttributeError) as exc:
        detail = f"syft output has an unexpected shape ({exc!r})"
        return outcome(asset, Method.SBOM_VERSION, MethodStatus.ERROR, detail)

    extra: dict[str, Any] = {"raw": sanitize.syft(document), "tool": tool, "scanned": scanned}
    if unfixed:
        return outcome(
            asset, Method.SBOM_VERSION, MethodStatus.PRESENT, "; ".join(unfixed), **extra
        )
    names = ", ".join(package.name for package in fix.packages)
    detail = "; ".join(fixed) or f"no {names} package among {len(artifacts)} packages"
    return outcome(asset, Method.SBOM_VERSION, MethodStatus.NOT_PRESENT, detail, **extra)
