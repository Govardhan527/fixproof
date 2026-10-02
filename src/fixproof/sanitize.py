"""Strip tool output down to what the evidence bundle may store (ADR-0007 item 7).

Both tools embed the raw image config (which holds the image's environment variables), the raw
manifest, labels and annotations, and their own configuration (which can carry registry
settings); Syft can list files and their contents; Grype names the local DB path. None of that
is package metadata, so none of it is stored (SPEC_NOTES §17).
"""

import copy
from typing import Any

_IMAGE_FIELDS = ("config", "manifest", "labels", "annotations")


def _drop(mapping: Any, *keys: str) -> None:
    if isinstance(mapping, dict):
        for key in keys:
            mapping.pop(key, None)


def syft(document: dict[str, Any]) -> dict[str, Any]:
    clean = copy.deepcopy(document)
    _drop(clean, "files")
    _drop(clean.get("source", {}).get("metadata"), *_IMAGE_FIELDS)
    _drop(clean.get("descriptor"), "configuration")
    return clean


def grype(document: dict[str, Any]) -> dict[str, Any]:
    clean = copy.deepcopy(document)
    _drop(clean.get("source", {}).get("target"), *_IMAGE_FIELDS)
    descriptor = clean.get("descriptor", {})
    _drop(descriptor, "configuration")
    _drop(descriptor.get("db", {}).get("status") if isinstance(descriptor, dict) else None, "path")
    return clean
