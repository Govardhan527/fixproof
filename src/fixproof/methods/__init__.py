"""The two evidence methods (ADR-0007 items 3 and 4) and what each one hands back."""

import json
from dataclasses import dataclass, field
from typing import Any

from fixproof.model import Asset, BuildAsset, ImageRef, Method, MethodResult, MethodStatus
from fixproof.platforms import Target
from fixproof.tools import ToolRun, last_line


class Unusable(Exception):
    """The tool's output cannot be used; the message becomes the method's error detail."""


@dataclass(frozen=True)
class MethodOutcome:
    """A method's result plus what the evidence bundle records about how it was reached."""

    result: MethodResult
    raw: dict[str, Any] | None = None  # sanitised tool output, stored as evidence
    tool: dict[str, Any] = field(default_factory=dict)  # tool and data versions
    scanned: dict[str, str] = field(default_factory=dict)  # manifest digest and platform
    platform: str = ""  # the platform this outcome is about (ADR-0014), set by fixproof.check
    digest: str = ""  # that platform's manifest digest


def outcome(
    asset: Asset, method: Method, status: MethodStatus, detail: str, **extra: Any
) -> MethodOutcome:
    result = MethodResult(asset=asset, method=method, status=status, detail=detail)
    return MethodOutcome(result=result, **extra)


def parse_output(name: str, run: ToolRun) -> dict[str, Any]:
    """The tool's JSON document, or Unusable with the reason."""
    if run.problem:
        raise Unusable(run.problem)
    if run.exit_code != 0:
        raise Unusable(f"{name} exited {run.exit_code}: {last_line(run.stderr)}")
    try:
        document = json.loads(run.stdout)
    except ValueError as exc:
        raise Unusable(f"{name} output is not JSON") from exc
    if not isinstance(document, dict):
        raise Unusable(f"{name} output is not a JSON object")
    return document


def target(asset: Asset, platform: Target | None = None) -> tuple[str, ImageRef | None]:
    """The tools' argument for an asset, and the digest they must have read, if one is known.

    A registry image is read by digest (`registry:`); a local build by the source the user gave,
    which has no registry digest to check against (ADR-0012 item 2). A platform target from
    `fixproof.platforms` (ADR-0014) names its own argument and manifest digest.
    """
    if platform is not None:
        return platform.argument, platform.image
    if isinstance(asset, BuildAsset):
        return asset.source, None
    if asset.image is None:
        raise ValueError("the methods need an asset with an image digest")
    return f"registry:{asset.image.reference}", asset.image


def scanned_image(name: str, metadata: Any, image: ImageRef | None) -> dict[str, str]:
    """Check the tool scanned the requested digest (ADR-0007 item 6) and say what it scanned."""
    if not isinstance(metadata, dict):
        raise Unusable(f"{name} did not report an image source")
    manifest = str(metadata.get("manifestDigest", ""))
    repo_digests = [str(d) for d in metadata.get("repoDigests") or []]
    if (
        image is not None
        and image.digest != manifest
        and not any(d.endswith("@" + image.digest) for d in repo_digests)
    ):
        raise Unusable(f"{name} scanned {manifest or 'an unknown digest'}, not {image.digest}")
    return {
        "image_id": str(metadata.get("imageID", "")),
        "manifest_digest": manifest,
        "platform": f"{metadata.get('os', '?')}/{metadata.get('architecture', '?')}"
        + (f"/{metadata['variant']}" if metadata.get("variant") else ""),
    }
