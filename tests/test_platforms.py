"""Which platforms of an image are checked (ADR-0014): `fixproof.platforms.plan`.

The fake `crane` answers with synthetic manifests whose bytes hash to their digests, as the real
one does; an index carries BuildKit attestation entries like Docker Hub's (SPEC_NOTES §20).
"""

import json
from collections.abc import Mapping, Sequence

import pytest

from fixproof.model import BuildAsset, ImageAsset, ImageRef, WorkloadAsset, normalise_platform
from fixproof.platforms import LINUX_ONLY, NOT_LISTED, plan
from fixproof.tools import ToolRun
from tool_outputs import MANIFESTS, OCI_INDEX, OCI_MANIFEST, crane, index_digest, manifest_digest

AMD64, ARM64, ARMV6 = (manifest_digest(f"app {p}") for p in ("amd64", "arm64", "arm/v6"))
INDEX = index_digest([(AMD64, "linux/amd64"), (ARM64, "linux/arm64/v8"), (ARMV6, "linux/arm/v6")])


def ref(digest: str) -> ImageRef:
    return ImageRef(registry="docker.io", repository="team/app", digest=digest)


def asset(digest: str) -> ImageAsset:
    return ImageAsset(image=ref(digest))


def fake_crane(calls: list[list[str]] | None = None, **answers: ToolRun) -> object:
    def run(name: str, args: Sequence[str], env: Mapping[str, str]) -> ToolRun:
        assert name == "crane", f"only crane may run while listing platforms, not {name}"
        if calls is not None:
            calls.append(list(args))
        return answers.get("answer") or crane(args[1])

    return run


def registered(document: dict[str, object]) -> str:
    """The digest of an arbitrary document, served by the fake crane."""
    import hashlib

    data = json.dumps(document).encode()
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    MANIFESTS[digest] = data
    return digest


def entry(kind: str, digest: str, arch: str) -> dict[str, object]:
    return {"mediaType": kind, "digest": digest, "platform": {"os": "linux", "architecture": arch}}


def index_of(*entries: dict[str, object]) -> str:
    return registered({"mediaType": OCI_INDEX, "manifests": list(entries)})


DENIED = "fetching manifest x: UNAUTHORIZED: authentication required"


def test_a_single_platform_image_is_one_target_read_by_its_own_digest() -> None:
    calls: list[list[str]] = []
    found = plan(asset(AMD64), None, fake_crane(calls))  # type: ignore[arg-type]
    assert calls == [["manifest", f"docker.io/team/app@{AMD64}"]]
    (target,) = found.targets
    assert (target.argument, target.image, target.platform) == (
        f"registry:docker.io/team/app@{AMD64}",
        ref(AMD64),
        None,  # the tools report it
    )
    assert (found.not_checked, found.problem) == ((), None)


def test_every_linux_platform_of_an_index_is_checked_through_its_own_manifest() -> None:
    found = plan(asset(INDEX), None, fake_crane())  # type: ignore[arg-type]
    assert [(t.platform, t.image) for t in found.targets] == [
        ("linux/amd64", ref(AMD64)),
        ("linux/arm64/v8", ref(ARM64)),
        ("linux/arm/v6", ref(ARMV6)),
    ]  # the attestation entries are not platforms
    assert all(t.argument == f"registry:{t.image.reference}" for t in found.targets if t.image)
    assert (found.not_checked, found.problem) == ((), None)


@pytest.mark.parametrize(
    ("wanted", "checked"),
    [
        (["linux/arm64"], ["linux/arm64/v8"]),  # arm64 is arm64/v8
        (["linux/amd64/v1", "linux/arm/v6"], ["linux/amd64", "linux/arm/v6"]),
        (["linux/arm64/v8", "linux/s390x"], ["linux/arm64/v8"]),  # absent ones are just absent
    ],
)
def test_platforms_limit_which_entries_of_an_index_are_checked(
    wanted: list[str], checked: list[str]
) -> None:
    found = plan(asset(INDEX), wanted, fake_crane())  # type: ignore[arg-type]
    assert [t.platform for t in found.targets] == checked
    left = {n.platform for n in found.not_checked}
    assert left == {"linux/amd64", "linux/arm64/v8", "linux/arm/v6"} - set(checked)
    assert {n.reason for n in found.not_checked} == {NOT_LISTED}


def test_an_index_with_none_of_the_platforms_is_a_problem_naming_them() -> None:
    found = plan(asset(INDEX), ["linux/s390x"], fake_crane())  # type: ignore[arg-type]
    assert found.targets == ()
    assert found.problem is not None
    assert found.problem.startswith("no platform to check: ")
    assert "linux/amd64 (not in platforms)" in found.problem
    assert len(found.not_checked) == 3


def test_other_operating_systems_are_named_and_not_checked() -> None:
    windows = manifest_digest("app windows")
    mixed = index_digest([(AMD64, "linux/amd64"), (windows, "windows/amd64")])
    found = plan(asset(mixed), None, fake_crane())  # type: ignore[arg-type]
    assert [t.platform for t in found.targets] == ["linux/amd64"]
    (left,) = found.not_checked
    assert (left.platform, left.digest, left.reason) == ("windows/amd64", windows, LINUX_ONLY)
    only_windows = index_digest([(windows, "windows/amd64")])
    found = plan(asset(only_windows), None, fake_crane())  # type: ignore[arg-type]
    assert found.problem == f"no platform to check: windows/amd64 ({LINUX_ONLY})"


def test_an_entry_listed_twice_is_checked_once() -> None:
    twice = index_digest([(AMD64, "linux/amd64"), (AMD64, "linux/amd64")], attestations=False)
    found = plan(asset(twice), None, fake_crane())  # type: ignore[arg-type]
    assert [t.image for t in found.targets] == [ref(AMD64)]


def test_an_entry_of_unknown_media_type_is_named_and_not_checked() -> None:
    odd = index_of(
        entry(OCI_MANIFEST, AMD64, "amd64"), entry("application/example", ARM64, "arm64")
    )
    found = plan(asset(odd), None, fake_crane())  # type: ignore[arg-type]
    assert [t.platform for t in found.targets] == ["linux/amd64"]
    assert [(n.platform, n.reason) for n in found.not_checked] == [
        ("linux/arm64", "not an image (application/example)")
    ]


def test_a_docker_manifest_list_without_media_types_on_its_documents_is_read() -> None:
    plain = registered(
        {
            "manifests": [
                {
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "digest": AMD64,
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ]
        }
    )
    found = plan(asset(plain), None, fake_crane())  # type: ignore[arg-type]
    assert [t.platform for t in found.targets] == ["linux/amd64"]


NESTED = index_of(entry(OCI_INDEX, INDEX, "amd64"))
NO_PLATFORM = index_of({"mediaType": OCI_MANIFEST, "digest": AMD64})
BAD_DIGEST = index_of(entry(OCI_MANIFEST, "sha512:00", "amd64"))
NOT_A_LIST = registered({"mediaType": OCI_INDEX, "manifests": {"amd64": AMD64}})
NOT_AN_ENTRY = registered({"mediaType": OCI_INDEX, "manifests": ["sha256:00"]})
WRONG_TYPE = registered({"mediaType": OCI_MANIFEST, "manifests": []})
NEITHER = registered({"schemaVersion": 2})
ARRAY = registered([])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("digest", "answer", "reason"),
    [
        (AMD64, ToolRun(0, b"", "", problem="crane not found on PATH"), "crane not found on PATH"),
        (AMD64, ToolRun(1, b"", f"Error: {DENIED}\n"), f"crane exited 1: Error: {DENIED}"),
        (AMD64, ToolRun(0, MANIFESTS[ARM64], ""), f"crane read does not hash to {AMD64}"),
        ("sha256:" + "0" * 64, ToolRun(0, b"not json", ""), "does not hash to"),
        (NESTED, None, "holds another index"),
        (NO_PLATFORM, None, f"the image index entry {AMD64} names no platform"),
        (BAD_DIGEST, None, "'sha512:00' is not a sha256 digest"),
        (NOT_A_LIST, None, "the image index has no list of manifests"),
        (NOT_AN_ENTRY, None, "an image index entry is not an object"),
        (WRONG_TYPE, None, f"not an image manifest or image index (media type '{OCI_MANIFEST}')"),
        (NEITHER, None, "not an image manifest or image index (media type None)"),
        (ARRAY, None, "the manifest is not a JSON object"),
    ],
)  # fmt: skip
def test_an_image_whose_platforms_cannot_be_listed_is_a_problem_with_the_reason(
    digest: str, answer: ToolRun | None, reason: str
) -> None:
    run = fake_crane(answer=answer) if answer else fake_crane()
    found = plan(asset(digest), None, run)  # type: ignore[arg-type]
    assert found.targets == ()
    assert found.problem is not None
    assert found.problem.startswith("the image's platforms could not be listed: ")
    assert reason in found.problem


def test_a_manifest_that_is_not_json_is_a_problem() -> None:
    data = b"{not json"
    import hashlib

    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    found = plan(asset(digest), None, fake_crane(answer=ToolRun(0, data, "")))  # type: ignore[arg-type]
    assert found.problem == "the image's platforms could not be listed: the manifest is not JSON"


def test_a_local_build_is_one_target_and_crane_never_runs() -> None:
    found = plan(BuildAsset(source="docker:app:ci"), ["linux/arm64"], fake_crane([]))  # type: ignore[arg-type]
    (target,) = found.targets
    assert (target.argument, target.image, target.platform) == ("docker:app:ci", None, None)


def test_an_asset_without_an_image_has_no_platforms() -> None:
    pending = WorkloadAsset(cluster="c", namespace="n", pod="p", container="app", image=None)
    with pytest.raises(ValueError, match="no platforms"):
        plan(pending, None, fake_crane())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("given", "normal"),
    [
        ("linux/amd64", "linux/amd64"),
        ("linux/amd64/v1", "linux/amd64"),
        ("linux/amd64/v2", "linux/amd64/v2"),
        ("linux/arm64", "linux/arm64"),
        ("linux/arm64/v8", "linux/arm64"),
        ("linux/arm64/8", "linux/arm64"),
        ("linux/arm64/v9", "linux/arm64/v9"),
        ("linux/arm", "linux/arm/v7"),
        ("linux/arm/7", "linux/arm/v7"),
        ("linux/arm/v7", "linux/arm/v7"),
        ("linux/arm/6", "linux/arm/v6"),
        ("linux/arm/v6", "linux/arm/v6"),
        ("linux/arm/5", "linux/arm/v5"),
        ("linux/arm/8", "linux/arm/v8"),
        ("linux/i386", "linux/386"),
        ("Linux/S390X", "linux/s390x"),
        ("windows/amd64", "windows/amd64"),
    ],
)
def test_platform_names_are_normalised_as_containerd_does(given: str, normal: str) -> None:
    assert normalise_platform(given) == normal


def test_an_unknown_unknown_entry_is_not_a_platform_even_without_the_annotation() -> None:
    unknown = {"os": "unknown", "architecture": "unknown"}
    bare = index_of(
        entry(OCI_MANIFEST, AMD64, "amd64"),
        {"mediaType": OCI_MANIFEST, "digest": ARM64, "platform": unknown},
    )
    found = plan(asset(bare), None, fake_crane())  # type: ignore[arg-type]
    assert [t.platform for t in found.targets] == ["linux/amd64"]
    assert found.not_checked == ()
