import json
from importlib.resources import files
from pathlib import Path

import pytest
import yaml

from fixproof.inputs import load_fix, load_scope
from fixproof.validation import build_validator
from generate_schemas import FORMATS, ID_BASE, main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_committed_schemas_match_the_models() -> None:
    assert main(["--check"]) == 0


def test_schema_ids_carry_the_format_and_version() -> None:
    for name, (_, version) in FORMATS.items():
        path = files("fixproof") / "schemas" / f"{name}.schema.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["$id"] == f"{ID_BASE}/{name}/{version}"
        build_validator(schema)  # each is a valid 2020-12 schema


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("fix/*.yaml")), ids=lambda p: p.name)
def test_fix_examples_pass_the_loader(path: Path) -> None:
    cve = yaml.safe_load(path.read_text(encoding="utf-8"))["cve"]
    assert load_fix(path, cve).cve == cve


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("scope/*.yaml")), ids=lambda p: p.name)
def test_scope_examples_pass_the_loader(path: Path) -> None:
    assert load_scope(path).registries
