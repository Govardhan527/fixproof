"""M2 integration: real Syft and Grype against the fixture images (ADR-0007 items 9 and 10).

Needs FIXPROOF_IT_IMAGES: the JSON written by scripts/build_fixtures.py. The CI `integration` job
builds the images, starts the registries and sets it; locally these tests are skipped without
it, and in CI (CI=true) a missing value fails them instead, so a broken setup cannot pass.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from fixproof.model import ImageRef
from fixproof.validation import check_openvex

pytestmark = pytest.mark.integration

CVE = "CVE-2023-32681"
EXPECTED = {
    "requests-2.30.0": "still_affected",
    "requests-2.25.1": "still_affected",
    "requests-2.31.0": "fixed",
    "requests-2.32.3": "fixed",
    "no-requests": "fixed",
    "two-copies": "still_affected",
    "venv-only": "still_affected",
    "auth/requests-2.31.0": "unknown",
}


@pytest.fixture(scope="module")
def images() -> dict[str, str]:
    path = os.environ.get("FIXPROOF_IT_IMAGES")
    if not path:
        if os.environ.get("CI"):
            pytest.fail("FIXPROOF_IT_IMAGES is not set; the integration setup did not run")
        pytest.skip("FIXPROOF_IT_IMAGES is not set (needs Docker and scripts/build_fixtures.py)")
    data: dict[str, str] = json.loads(Path(path).read_text(encoding="utf-8"))
    return data


def verify(
    tmp_path: Path, images: dict[str, str], names: list[str], fixed_version: str
) -> tuple[int, dict[str, Any], Path]:
    references = [images[name] for name in names]
    registries = sorted({ImageRef.parse(ref).registry for ref in references})
    (tmp_path / "fix.yaml").write_text(
        f'schema_version: "1.0.0"\ncve: {CVE}\npackages:\n  - ecosystem: pypi\n'
        f'    name: requests\n    fixed_version: "{fixed_version}"\n',
        encoding="utf-8",
    )
    (tmp_path / "scope.yaml").write_text(
        'schema_version: "1.0.0"\n'
        f"registries: [{', '.join(registries)}]\n"
        "images:\n" + "".join(f"  - {ref}\n" for ref in references),
        encoding="utf-8",
    )
    no_credentials = tmp_path / "docker-config"
    no_credentials.mkdir()
    out = tmp_path / "out"
    done = subprocess.run(
        [
            sys.executable, "-c", "from fixproof.cli import main; main()",
            "verify", "--cve", CVE, "--fix", str(tmp_path / "fix.yaml"),
            "--scope", str(tmp_path / "scope.yaml"), "--out", str(out),
            "--author", "fixproof integration tests", "--json",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "DOCKER_CONFIG": str(no_credentials)},
        check=False,
        timeout=3600,
    )  # fmt: skip
    assert done.stdout, done.stderr
    return done.returncode, json.loads(done.stdout), out


def test_eight_fixture_images(tmp_path: Path, images: dict[str, str]) -> None:
    code, report, out = verify(tmp_path, images, list(EXPECTED), "2.31.0")
    by_reference = {item["asset"]: item for item in report["assets"]}
    for name, verdict in EXPECTED.items():
        item = by_reference[images[name]]
        assert item["verdict"] == verdict, (name, item["reason"])
    assert report["summary"] == {"fixed": 3, "still_affected": 4, "unknown": 1}
    assert code == 1
    check_openvex(json.loads((out / "openvex.json").read_text()))
    bundle = json.loads((out / "bundle.json").read_text())
    tools = {tool["name"]: tool for tool in bundle["tools"]}
    assert tools["syft"]["version"] == "1.54.0"
    assert tools["grype"]["version"] == "0.119.0"
    assert tools["grype"]["db"]["schemaVersion"].startswith("v6.")
    for record in bundle["assets"]:  # each fixture is built for one platform (ADR-0014)
        for platform in record["platforms"]:
            assert platform["platform"] == "linux/amd64", record["reason"]
            for scanned in platform["scanned"].values():
                assert scanned["platform"] == "linux/amd64"


def test_a_fix_claim_above_the_real_fix_is_a_disagreement(
    tmp_path: Path, images: dict[str, str]
) -> None:
    code, report, _ = verify(tmp_path, images, ["requests-2.31.0"], "2.32.0")
    (item,) = report["assets"]
    assert item["verdict"] == "unknown"
    assert item["reason"].startswith("the methods disagree.")
    assert code == 2
