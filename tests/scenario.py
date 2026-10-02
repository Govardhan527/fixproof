"""A three-image scenario used by the bundle, CLI and golden tests.

demo-app is vulnerable (requests 2.30.0), demo-fixed has requests 2.31.0, and demo-broken is an
image the tools cannot read (Grype exits 1), so the verdicts are still_affected, fixed and
unknown.
"""

import hashlib
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fixproof.canonical import to_json
from fixproof.model import ImageRef
from fixproof.tools import ToolRun
from tool_outputs import CVE, IMAGE, for_image, image_runner, output

START = datetime(2026, 10, 2, 9, 0, 0, tzinfo=UTC)
FINISH = datetime(2026, 10, 2, 9, 1, 30, tzinfo=UTC)
AUTHOR = "Example Vulnerability Management <vm@example.com>"


def image(repository: str) -> ImageRef:
    digest = "sha256:" + hashlib.sha256(repository.encode()).hexdigest()
    return ImageRef(registry="localhost:5001", repository=repository, digest=digest)


VULNERABLE, FIXED, BROKEN = IMAGE, image("fixproof/demo-fixed"), image("fixproof/demo-broken")
BROKEN_RUN = ToolRun(1, b"", "ERROR failed to fetch image: unexpected status 500\n")

FIX_YAML = f"""\
schema_version: "1.0.0"
cve: {CVE}
packages:
  - ecosystem: pypi
    name: requests
    fixed_version: "2.31.0"
"""
SCOPE_YAML = f"""\
schema_version: "1.0.0"
registries: [localhost:5001]
images:
  - {VULNERABLE.reference}
  - {FIXED.reference}
  - {BROKEN.reference}
"""


def answers() -> dict[str, dict[str, Any]]:
    return {
        VULNERABLE.reference: {
            "syft": output("syft", "vulnerable"),
            "grype": output("grype", "vulnerable"),
        },
        FIXED.reference: {
            "syft": for_image(output("syft", "fixed"), FIXED),
            "grype": for_image(output("grype", "fixed"), FIXED),
        },
        BROKEN.reference: {
            "syft": for_image(output("syft", "fixed"), BROKEN),
            "grype": BROKEN_RUN,
        },
    }


def runner() -> Any:
    return image_runner(answers())


def install_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Put stand-in `syft` and `grype` on PATH that answer per image like the real tools."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    for tool in ("syft", "grype"):
        cases = []
        for reference, by_tool in answers().items():
            answer = by_tool[tool]
            if isinstance(answer, ToolRun):
                cases.append(
                    f'  "registry:{reference}") echo "{answer.stderr.strip()}" >&2; exit 1 ;;'
                )
            else:
                data = bin_dir / f"{tool}-{hashlib.sha256(reference.encode()).hexdigest()}.json"
                data.write_bytes(to_json(answer))
                cases.append(f'  "registry:{reference}") cat "{data}" ;;')
        script = bin_dir / tool
        script.write_text(
            '#!/bin/sh\ncase "$1" in\n'
            + "\n".join(cases)
            + '\n  *) echo "ERROR unknown image $1" >&2; exit 1 ;;\nesac\n',
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
