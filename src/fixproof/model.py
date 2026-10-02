"""Data contracts shared by every module (ADR-0005 item 3).

Every model is frozen and rejects unknown fields. Standards-derived patterns cite SPEC_NOTES.
"""

import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

# SPEC_NOTES §2: CVE JSON 5.2.0 `cveId`.
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
# SPEC_NOTES §15: OCI image-spec digest; fixproof accepts sha256 only.
DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
# SPEC_NOTES §15: OCI distribution-spec `<name>`.
REPOSITORY_PATTERN = r"^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$"
# SPEC_NOTES §15: distribution/reference `domain := host [':' port-number]`, host as a domain
# name or IPv4 address (bracketed IPv6 hosts are not accepted).
_COMPONENT = r"([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
REGISTRY_PATTERN = rf"^{_COMPONENT}(\.{_COMPONENT})*(:[0-9]+)?$"

CveId = Annotated[str, StringConstraints(pattern=CVE_PATTERN)]
Registry = Annotated[str, StringConstraints(pattern=REGISTRY_PATTERN)]
Text = Annotated[str, StringConstraints(min_length=1)]


class Contract(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def _is_registry_segment(segment: str) -> bool:
    """distribution/reference's test for "this first segment is a host" (SPEC_NOTES §15)."""
    return segment == "localhost" or any(c in segment for c in ".:") or segment != segment.lower()


class ImageRef(Contract):
    """An image by registry, repository and digest. Tags are never part of the identity."""

    registry: Registry
    repository: Annotated[str, StringConstraints(pattern=REPOSITORY_PATTERN)]
    digest: Annotated[str, StringConstraints(pattern=DIGEST_PATTERN)]

    @classmethod
    def parse(cls, reference: str) -> Self:
        """Parse `registry/repository@sha256:<hex>`. Raises ValueError with the reason."""
        name, at, digest = reference.partition("@")
        if not at:
            raise ValueError(f"{reference!r} has no @sha256 digest; images are pinned by digest")
        registry, slash, repository = name.partition("/")
        if not slash or not _is_registry_segment(registry):
            raise ValueError(
                f"{reference!r} has no registry host; write it in full, e.g. "
                "registry.example.com/team/app@sha256:..."
            )
        if ":" in repository:
            raise ValueError(f"{reference!r} has a tag; give the digest only")
        try:
            return cls(registry=registry, repository=repository, digest=digest)
        except ValidationError as exc:
            fields = sorted({str(e["loc"][0]) for e in exc.errors()})
            raise ValueError(f"{reference!r} has an invalid {' and '.join(fields)}") from None

    @property
    def reference(self) -> str:
        return f"{self.registry}/{self.repository}@{self.digest}"


class ImageAsset(Contract):
    """An image named in scope.yaml."""

    kind: Literal["image"] = "image"
    image: ImageRef


class WorkloadAsset(Contract):
    """A container in a running pod. `image` is None when its digest could not be resolved."""

    kind: Literal["workload"] = "workload"
    cluster: Text
    namespace: Text
    pod: Text
    container: Text
    image: ImageRef | None


Asset = Annotated[ImageAsset | WorkloadAsset, Field(discriminator="kind")]


class Method(StrEnum):
    GRYPE = "grype"
    SBOM_VERSION = "sbom_version"


class MethodStatus(StrEnum):
    """What one evidence method says about the vulnerable component in one asset."""

    PRESENT = "present"
    NOT_PRESENT = "not_present"
    ERROR = "error"


class MethodResult(Contract):
    asset: Asset
    method: Method
    status: MethodStatus
    detail: Text
    raw_ref: str | None = None


class Verdict(StrEnum):
    FIXED = "fixed"
    STILL_AFFECTED = "still_affected"
    UNKNOWN = "unknown"


class AssetVerdict(Contract):
    asset: Asset
    verdict: Verdict
    reason: Text
    results: tuple[MethodResult, ...] = ()


def is_cve_id(value: str) -> bool:
    return re.fullmatch(CVE_PATTERN, value) is not None
