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
DIGEST = "sha256:" + hashlib.sha256(b"fixproof/demo-app").hexdigest()
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
