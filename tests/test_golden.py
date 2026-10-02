"""Golden VEX files: examples/openvex/ holds exactly what the writer produces for fixed inputs.

`make schemas` validates the same files against the official OpenVEX schema. Regenerate after an
intended change with:
    FIXPROOF_UPDATE_GOLDEN=1 make test
"""

import os

import pytest

from fixproof.canonical import to_json
from fixproof.vex import build_document
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
