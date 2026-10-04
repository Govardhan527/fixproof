"""Fake tool runs built from the trimmed real Syft 1.54.0 and Grype 0.119.0 outputs.

tests/fixtures/tools/*.json were derived from real runs against `requests` 2.30.0 and 2.31.0
(SPEC_NOTES §17), with a synthetic image identity, local paths replaced, and a marker
(`MARKER=must-not-be-stored`) planted in the image config and a file's contents so the tests can
prove neither reaches the evidence bundle.
"""

import copy
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from fixproof.inputs import FixFile
from fixproof.model import ImageAsset, ImageRef
from fixproof.tools import ToolRun

FIXTURES = Path(__file__).parent / "fixtures" / "tools"
CVE = "CVE-2023-32681"  # real advisory; Grype must know it (SPEC_NOTES §17)
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
# Every synthetic manifest by its digest, so the fake `crane` can answer for any image built here
MANIFESTS: dict[str, bytes] = {}


def _register(document: dict[str, Any]) -> str:
    data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    MANIFESTS[digest] = data
    return digest


def manifest_digest(name: str) -> str:
    """The digest of a synthetic single-platform image manifest named `name`."""
    config = "sha256:" + hashlib.sha256(name.encode()).hexdigest()
    return _register(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config,
                "size": 1,
            },
            "layers": [],
            "annotations": {"org.opencontainers.image.title": name},
        }
    )


def index_digest(entries: Sequence[tuple[str, str]], attestations: bool = True) -> str:
    """The digest of a synthetic image index of (digest, os/arch[/variant]) entries; each platform
    gets a BuildKit attestation entry too, as Docker Hub images have (SPEC_NOTES §20)."""
    manifests: list[dict[str, Any]] = []
    for digest, platform in entries:
        os_name, arch, *variant = platform.split("/")
        described = {
            "os": os_name,
            "architecture": arch,
            **({"variant": variant[0]} if variant else {}),
        }
        manifests.append(
            {"mediaType": OCI_MANIFEST, "digest": digest, "size": 1, "platform": described}
        )
        if attestations:
            manifests.append(
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": manifest_digest(f"attestation of {digest}"),
                    "size": 1,
                    "annotations": {
                        "vnd.docker.reference.digest": digest,
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                    "platform": {"architecture": "unknown", "os": "unknown"},
                }
            )
    return _register({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests})


def crane(reference: str) -> ToolRun:
    """What `crane manifest` prints for a synthetic image, or its error for any other."""
    digest = reference.partition("@")[2]
    if digest in MANIFESTS:
        return ToolRun(0, MANIFESTS[digest], "")
    return ToolRun(
        1, b"", f"Error: fetching manifest {reference}: MANIFEST_UNKNOWN: manifest unknown\n"
    )


DIGEST = manifest_digest("fixproof/demo-app")
IMAGE = ImageRef(registry="localhost:5001", repository="fixproof/demo-app", digest=DIGEST)
ASSET = ImageAsset(image=IMAGE)
MARKER = "must-not-be-stored"


def output(tool: str, state: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURES / f"{tool}-requests-{state}.json").read_text(encoding="utf-8")
    )
    return data


def runner(
    documents: Mapping[str, dict[str, Any] | ToolRun],
    calls: list[tuple[str, list[str], dict[str, str]]] | None = None,
) -> Callable[[str, Sequence[str], Mapping[str, str]], ToolRun]:
    """A fake `run_tool` that answers each tool with a document (or a prepared ToolRun)."""

    def run(name: str, args: Sequence[str], env: Mapping[str, str]) -> ToolRun:
        if calls is not None:
            calls.append((name, list(args), dict(env)))
        if name == "crane" and name not in documents:
            return crane(args[1])
        answer = documents[name]
        if isinstance(answer, ToolRun):
            return answer
        return ToolRun(0, json.dumps(answer).encode(), "")

    return run


def edited(document: dict[str, Any], edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    edit(changed)
    return changed


def requests_fix(**package: str) -> FixFile:
    fields = {"ecosystem": "pypi", "name": "requests", "fixed_version": "2.31.0", **package}
    return FixFile.model_validate({"schema_version": "1.0.0", "cve": CVE, "packages": [fields]})


def for_image(document: dict[str, Any], image: ImageRef) -> dict[str, Any]:
    """The same tool output, as if it came from scanning `image` (an index digest)."""
    changed = copy.deepcopy(document)
    reference = image.reference
    if "artifacts" in changed:  # syft
        changed["source"]["name"] = f"{image.registry}/{image.repository}"
        changed["source"]["version"] = image.digest
        metadata = changed["source"]["metadata"]
    else:  # grype
        metadata = changed["source"]["target"]
    metadata["userInput"] = reference
    metadata["repoDigests"] = [reference]
    return changed


def image_runner(
    by_reference: Mapping[str, Mapping[str, dict[str, Any] | ToolRun]],
) -> Callable[[str, Sequence[str], Mapping[str, str]], ToolRun]:
    """A fake `run_tool` that answers per tool and per image (`registry:<reference>`)."""

    def run(name: str, args: Sequence[str], env: Mapping[str, str]) -> ToolRun:
        if name == "crane":
            reference = args[1]
            answer = by_reference.get(reference, {}).get("crane")
            return answer if isinstance(answer, ToolRun) else crane(reference)
        reference = args[0].removeprefix("registry:")
        answer = by_reference[reference][name]
        if isinstance(answer, ToolRun):
            return answer
        return ToolRun(0, json.dumps(answer).encode(), "")

    return run
