"""Golden VEX files: examples/openvex/ holds exactly what the writer produces for fixed inputs.

`make schemas` validates the same files against the official OpenVEX schema. Regenerate after an
intended change with:
    FIXPROOF_UPDATE_GOLDEN=1 make test
"""

import os
from pathlib import Path

import pytest
import yaml

from fixproof.bundle import write_bundle
from fixproof.canonical import to_json
from fixproof.cyclonedx import build_bom
from fixproof.inputs import FixFile, ScopeFile
from fixproof.report import verify_summary
from fixproof.verify import assess
from fixproof.vex import build_document
from scenario import FINISH, FIX_YAML, KEV, SCOPE_YAML, START, runner
from tool_outputs import CVE
from vex_cases import AUTHOR, EXAMPLES, GOLDEN, NOW, TOOL_VERSION, example_fix

GOLDEN_DIR = EXAMPLES / "openvex"
UPDATE = os.environ.get("FIXPROOF_UPDATE_GOLDEN") == "1"


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_golden_vex(name: str) -> None:
    fix_name, verdicts = GOLDEN[name]
    document = build_document(
        example_fix(fix_name), verdicts, author=AUTHOR, now=NOW, tool_version=TOOL_VERSION
    )
    path = GOLDEN_DIR / f"{name}.json"
    if UPDATE:
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(to_json(document))
    assert path.read_bytes() == to_json(document), f"{path} is stale; see this module's docstring"


def test_every_golden_file_has_a_case() -> None:
    assert {path.stem for path in GOLDEN_DIR.glob("*.json")} == set(GOLDEN)


def test_golden_files_are_never_regenerated_in_ci() -> None:
    assert not (UPDATE and os.environ.get("CI")), "FIXPROOF_UPDATE_GOLDEN must not be set in CI"


@pytest.mark.parametrize("name", ["bundle", "manifest", "report"])
def test_golden_bundle(tmp_path: Path, name: str) -> None:
    """The three-image scenario's bundle.json and manifest.json (tests/scenario.py)."""
    fix = FixFile.model_validate(yaml.safe_load(FIX_YAML))
    assessments = assess(fix, ScopeFile.model_validate(yaml.safe_load(SCOPE_YAML)), runner())
    vex = build_document(
        fix, [a.verdict for a in assessments], author=AUTHOR, now=FINISH, tool_version=TOOL_VERSION
    )
    write_bundle(
        tmp_path / "out",
        cve=CVE,
        fix_bytes=FIX_YAML.encode(),
        scope_bytes=SCOPE_YAML.encode(),
        assessments=assessments,
        vex=vex,
        cyclonedx=build_bom(
            fix, [a.verdict for a in assessments], now=FINISH, tool_version=TOOL_VERSION
        ),
        started=START,
        finished=FINISH,
        kev=KEV,
        tool_version=TOOL_VERSION,
    )
    suffix = ".html" if name == "report" else ".json"
    produced = (tmp_path / "out" / f"{name}{suffix}").read_bytes()
    path = EXAMPLES / ("html" if name == "report" else name) / f"three-images{suffix}"
    if UPDATE:
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(produced)
    assert path.read_bytes() == produced, f"{path} is stale; see this module's docstring"


def test_golden_verify_summary() -> None:
    """The `verify --json` summary of the three-image scenario."""
    fix = FixFile.model_validate(yaml.safe_load(FIX_YAML))
    assessments = assess(fix, ScopeFile.model_validate(yaml.safe_load(SCOPE_YAML)), runner())
    produced = to_json(
        verify_summary(CVE, "evidence", [a.verdict for a in assessments], KEV).model_dump(
            mode="json"
        )
    )
    path = EXAMPLES / "verify-summary" / "three-images.json"
    if UPDATE:
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(produced)
    assert path.read_bytes() == produced, f"{path} is stale; see this module's docstring"


def test_golden_cyclonedx() -> None:
    """The three-image scenario as CycloneDX 1.6 VEX (examples/cyclonedx/)."""
    fix = FixFile.model_validate(yaml.safe_load(FIX_YAML))
    assessments = assess(fix, ScopeFile.model_validate(yaml.safe_load(SCOPE_YAML)), runner())
    produced = to_json(
        build_bom(fix, [a.verdict for a in assessments], now=FINISH, tool_version=TOOL_VERSION)
    )
    path = EXAMPLES / "cyclonedx" / "three-images.json"
    if UPDATE:
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(produced)
    assert path.read_bytes() == produced, f"{path} is stale; see this module's docstring"
