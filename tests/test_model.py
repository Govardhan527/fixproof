import pytest
from pydantic import TypeAdapter, ValidationError

from fixproof.model import (
    Asset,
    AssetVerdict,
    ImageAsset,
    ImageRef,
    Method,
    MethodResult,
    MethodStatus,
    Verdict,
    WorkloadAsset,
    is_cve_id,
)

DIGEST = "sha256:" + "0123456789abcdef" * 4


@pytest.mark.parametrize(
    ("reference", "registry", "repository"),
    [
        (f"registry.example.com/team/app@{DIGEST}", "registry.example.com", "team/app"),
        (f"localhost:5001/app@{DIGEST}", "localhost:5001", "app"),
        (f"localhost/app@{DIGEST}", "localhost", "app"),
        (f"10.0.0.7:5000/a.b/c-d__e@{DIGEST}", "10.0.0.7:5000", "a.b/c-d__e"),
        (f"Registry.Example/app@{DIGEST}", "Registry.Example", "app"),
    ],
)
def test_image_reference_parses(reference: str, registry: str, repository: str) -> None:
    ref = ImageRef.parse(reference)
    assert (ref.registry, ref.repository, ref.digest) == (registry, repository, DIGEST)
    assert ref.reference == reference


@pytest.mark.parametrize(
    ("reference", "reason"),
    [
        ("registry.example.com/app:1.0", "no @sha256 digest"),
        (f"app@{DIGEST}", "no registry host"),
        (f"team/app@{DIGEST}", "no registry host"),  # would mean Docker Hub
        (f"registry.example.com/app:1.0@{DIGEST}", "has a tag"),
        (f"registry.example.com/App@{DIGEST}", "invalid repository"),
        ("registry.example.com/app@sha256:ABC", "invalid digest"),
        (f"registry.example.com/app@sha512:{'a' * 128}", "invalid digest"),
        (f"-bad-.example.com/app@{DIGEST}", "invalid registry"),
    ],
)
def test_bad_image_references_are_rejected(reference: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        ImageRef.parse(reference)


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("CVE-2023-0286", True),
        ("CVE-2026-104286", True),
        ("CVE-2023-028", False),
        ("cve-2023-0286", False),
        ("CVE-23-0286", False),
        ("CVE-2023-0286 ", False),
    ],
)
def test_cve_id_pattern(value: str, valid: bool) -> None:
    assert is_cve_id(value) is valid


def test_assets_round_trip_through_their_discriminator() -> None:
    image = ImageRef.parse(f"localhost:5001/app@{DIGEST}")
    adapter: TypeAdapter[ImageAsset | WorkloadAsset] = TypeAdapter(Asset)
    for asset in (
        ImageAsset(image=image),
        WorkloadAsset(cluster="kind", namespace="web", pod="p-1", container="c", image=image),
        WorkloadAsset(cluster="kind", namespace="web", pod="p-2", container="c", image=None),
    ):
        assert adapter.validate_python(asset.model_dump()) == asset


def test_contracts_are_frozen_and_closed() -> None:
    asset = ImageAsset(image=ImageRef.parse(f"localhost:5001/app@{DIGEST}"))
    result = MethodResult(
        asset=asset, method=Method.GRYPE, status=MethodStatus.ERROR, detail="grype exited 1"
    )
    verdict = AssetVerdict(asset=asset, verdict=Verdict.UNKNOWN, reason="x", results=(result,))
    with pytest.raises(ValidationError, match="frozen"):
        verdict.reason = "y"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="Extra inputs"):
        AssetVerdict.model_validate({**verdict.model_dump(), "note": "x"})
    with pytest.raises(ValidationError, match="at least 1 character"):
        AssetVerdict(asset=asset, verdict=Verdict.UNKNOWN, reason="")
