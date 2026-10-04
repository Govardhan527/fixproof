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


def is_registry_host(segment: str) -> bool:
    """distribution/reference's test for "this first segment is a host" (SPEC_NOTES §15)."""
    return segment == "localhost" or any(c in segment for c in ".:") or segment != segment.lower()


def expand_docker_name(name: str) -> str:
    """Docker's familiar name in full, e.g. `nginx` -> `docker.io/library/nginx`.

    distribution/reference `splitDockerDomain` (SPEC_NOTES §12, §15): a first segment that is not
    a host means Docker Hub, `index.docker.io` is Docker Hub, and a single-segment name on Docker
    Hub gets `library/`. Used only for Docker Engine image IDs, never for `scope.yaml`.
    """
    first, slash, rest = name.partition("/")
    if slash and is_registry_host(first):
        domain, remote = ("docker.io" if first == "index.docker.io" else first), rest
    else:
        domain, remote = "docker.io", name
    if domain == "docker.io" and "/" not in remote:
        remote = f"library/{remote}"
    return f"{domain}/{remote}"


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
        if not slash or not is_registry_host(registry):
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
    owner: Text | None = Field(
        default=None, description="The pod's controller, e.g. Deployment/api (ADR-0010)."
    )

    @property
    def location(self) -> str:
        return f"{self.cluster}/{self.namespace}/{self.pod}/{self.container}"


class BuildAsset(Contract):
    """An image a CI job has just built, read where it was built (ADR-0012 item 2).

    `source` is the tool argument as given: `docker:NAME[:TAG]` (the local Docker daemon),
    `docker-archive:PATH` or `oci-archive:PATH`. It has no registry digest yet, so `image` is
    always None; what the tools read is recorded with each result.
    """

    kind: Literal["build"] = "build"
    source: Text
    image: None = None


Asset = Annotated[ImageAsset | WorkloadAsset | BuildAsset, Field(discriminator="kind")]


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


class PlatformVerdict(Contract):
    """One platform of an image (ADR-0014): the manifest the tools read and its verdict."""

    platform: Text = Field(description="os/architecture[/variant], e.g. linux/arm64.")
    digest: str = Field(description="The platform's manifest digest; empty if never read.")
    verdict: Verdict
    reason: Text
    results: tuple[MethodResult, ...] = ()


class NotChecked(Contract):
    """A platform of an image index that fixproof did not check, and why (ADR-0014)."""

    platform: Text
    digest: Text
    reason: Text


class AssetVerdict(Contract):
    asset: Asset
    verdict: Verdict
    reason: Text
    results: tuple[MethodResult, ...] = Field(
        default=(), description="Every method result behind the verdict, all platforms."
    )
    platforms: tuple[PlatformVerdict, ...] = ()
    not_checked: tuple[NotChecked, ...] = ()


# SPEC_NOTES §20: `os/architecture[/variant]` as an image index names a platform.
PLATFORM_PATTERN = r"^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9.]+)?$"
Platform = Annotated[str, StringConstraints(pattern=PLATFORM_PATTERN)]


def normalise_platform(platform: str) -> str:
    """The platform in containerd's normal form (SPEC_NOTES §20), for matching only.

    `amd64/v1` is `amd64`, `arm64/v8` is `arm64`, `arm` is `arm/v7`, `i386` is `386`.
    """
    os_name, _, rest = platform.lower().partition("/")
    arch, _, variant = rest.partition("/")
    if arch == "i386":
        arch, variant = "386", ""
    elif (arch, variant) in (("amd64", "v1"), ("arm64", "8"), ("arm64", "v8")):
        variant = ""
    elif arch == "arm" and variant in ("", "7"):
        variant = "v7"
    elif arch == "arm" and variant in ("5", "6", "8"):
        variant = f"v{variant}"
    return f"{os_name}/{arch}/{variant}" if variant else f"{os_name}/{arch}"


def is_cve_id(value: str) -> bool:
    return re.fullmatch(CVE_PATTERN, value) is not None
