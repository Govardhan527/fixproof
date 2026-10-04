"""Which platforms of an image to check (ADR-0014).

A registry image's manifest is read with `crane manifest`: go-containerregistry, the library Syft
and Grype read registries with, so the same Docker config, credential helpers and plain HTTP for
`localhost` apply, and fixproof never reads a credential itself. The bytes must hash to the
digest. An image manifest is one platform. In an image index each Linux entry is checked through
its own manifest digest, so the tools read exactly that platform; attestation entries are not
platforms (SPEC_NOTES §20). Entries for another operating system, or outside `platforms`, are
named as not checked. A local build is one platform, whatever the tools read.
"""

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from fixproof.model import Asset, BuildAsset, ImageRef, NotChecked, normalise_platform
from fixproof.tools import Runner, last_line, run_tool

# SPEC_NOTES §20: the OCI and Docker media types of an image index and an image manifest.
INDEX_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
MANIFEST_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
REFERENCE_TYPE, ATTESTATION = "vnd.docker.reference.type", "attestation-manifest"
LINUX_ONLY = "fixproof checks Linux platforms only"
NOT_LISTED = "not in platforms"


@dataclass(frozen=True)
class Target:
    """One platform to check: the tools' argument, the digest they must read (None for a local
    build), and the platform when the image index names it."""

    argument: str
    image: ImageRef | None
    platform: str | None = None


@dataclass(frozen=True)
class Plan:
    """The platforms to check, those left out, or why the image's platforms are not known."""

    targets: tuple[Target, ...] = ()
    not_checked: tuple[NotChecked, ...] = ()
    problem: str | None = None


def platform_name(platform: dict[str, Any]) -> str:
    """`os/architecture[/variant]` as the index names it."""
    name = f"{platform.get('os', '?')}/{platform.get('architecture', '?')}"
    return f"{name}/{platform['variant']}" if platform.get("variant") else name


# crane's error line: "Error: fetching manifest REF: GET URL: CODE: message" (SPEC_NOTES §20)
_CRANE_PREFIX = re.compile(r"^Error: fetching manifest \S+: (?:GET \S+: )?")


def _registry_answer(stderr: str) -> str:
    """The registry's answer from crane's error, without the reference and URL it repeats,
    so the answer (UNAUTHORIZED, MANIFEST_UNKNOWN, ...) survives the one-line limit."""
    return last_line(_CRANE_PREFIX.sub("", last_line(stderr, limit=4096)))


def _manifest(image: ImageRef, run: Runner) -> dict[str, Any]:
    """The manifest at the image's digest, or ValueError with the reason."""
    done = run("crane", ["manifest", image.reference], {})
    if done.problem:
        raise ValueError(done.problem)
    if done.exit_code != 0:
        raise ValueError(f"crane exited {done.exit_code}: {_registry_answer(done.stderr)}")
    if "sha256:" + hashlib.sha256(done.stdout).hexdigest() != image.digest:
        raise ValueError(f"the manifest crane read does not hash to {image.digest}")
    try:
        document = json.loads(done.stdout)
    except ValueError:
        raise ValueError("the manifest is not JSON") from None
    if not isinstance(document, dict):
        raise ValueError("the manifest is not a JSON object")
    return document


def _from_index(
    image: ImageRef, entries: Any, wanted: frozenset[str] | None
) -> tuple[list[Target], list[NotChecked]]:
    if not isinstance(entries, list):
        raise ValueError("the image index has no list of manifests")
    targets: list[Target] = []
    left_out: list[NotChecked] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("an image index entry is not an object")
        platform = entry.get("platform")
        annotations = entry.get("annotations") or {}
        if annotations.get(REFERENCE_TYPE) == ATTESTATION:
            continue
        digest, kind = str(entry.get("digest", "")), entry.get("mediaType")
        if kind in INDEX_TYPES:
            raise ValueError(f"the image index holds another index ({digest}), not supported")
        if not isinstance(platform, dict):
            raise ValueError(f"the image index entry {digest} names no platform")
        name = platform_name(platform)
        if platform.get("os") == "unknown" and platform.get("architecture") == "unknown":
            continue  # not a platform (SPEC_NOTES §20)
        if kind not in MANIFEST_TYPES:
            left_out.append(
                NotChecked(platform=name, digest=digest, reason=f"not an image ({kind})")
            )
        elif platform.get("os") != "linux":
            left_out.append(NotChecked(platform=name, digest=digest, reason=LINUX_ONLY))
        elif wanted is not None and normalise_platform(name) not in wanted:
            left_out.append(NotChecked(platform=name, digest=digest, reason=NOT_LISTED))
        elif all(t.image is None or t.image.digest != digest for t in targets):
            try:
                child = ImageRef(
                    registry=image.registry, repository=image.repository, digest=digest
                )
            except ValidationError:
                raise ValueError(
                    f"the image index entry {digest!r} is not a sha256 digest"
                ) from None
            targets.append(Target(f"registry:{child.reference}", child, name))
    return targets, left_out


def plan(asset: Asset, platforms: Sequence[str] | None = None, run: Runner = run_tool) -> Plan:
    """The platforms of `asset` to check; `platforms` limits which entries of an index count."""
    if isinstance(asset, BuildAsset):
        return Plan(targets=(Target(asset.source, None),))
    if asset.image is None:
        raise ValueError("an asset without an image digest has no platforms")
    image = asset.image
    wanted = frozenset(normalise_platform(p) for p in platforms) if platforms else None
    try:
        document = _manifest(image, run)
        media = document.get("mediaType")  # optional in OCI documents (SPEC_NOTES §20)
        if "manifests" in document and media in (None, *INDEX_TYPES):
            targets, left_out = _from_index(image, document["manifests"], wanted)
        elif "config" in document and "layers" in document and media in (None, *MANIFEST_TYPES):
            return Plan(targets=(Target(f"registry:{image.reference}", image),))
        else:
            raise ValueError(f"not an image manifest or image index (media type {media!r})")
    except ValueError as exc:
        return Plan(problem=f"the image's platforms could not be listed: {exc}")
    if not targets:
        listed = "; ".join(f"{n.platform} ({n.reason})" for n in left_out) or "none"
        return Plan(not_checked=tuple(left_out), problem=f"no platform to check: {listed}")
    return Plan(targets=tuple(targets), not_checked=tuple(left_out))
