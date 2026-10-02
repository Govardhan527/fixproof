"""The two evidence methods (ADR-0007 items 3 and 4) and what each one hands back."""

import json
from dataclasses import dataclass, field
from typing import Any

from fixproof.model import Asset, ImageRef, Method, MethodResult, MethodStatus
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


def scanned_image(name: str, metadata: Any, image: ImageRef) -> dict[str, str]:
    """Check the tool scanned the requested digest (ADR-0007 item 6) and say what it scanned."""
    if not isinstance(metadata, dict):
        raise Unusable(f"{name} did not report an image source")
    manifest = str(metadata.get("manifestDigest", ""))
    repo_digests = [str(d) for d in metadata.get("repoDigests") or []]
    if image.digest != manifest and not any(d.endswith("@" + image.digest) for d in repo_digests):
        raise Unusable(f"{name} scanned {manifest or 'an unknown digest'}, not {image.digest}")
    return {
        "manifest_digest": manifest,
        "platform": f"{metadata.get('os', '?')}/{metadata.get('architecture', '?')}",
    }
