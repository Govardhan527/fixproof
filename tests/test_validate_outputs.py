import json
from pathlib import Path
from typing import Any

import pytest

from validate_outputs import main

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["schema_version"],
    "properties": {"schema_version": {"type": "string"}},
}


def write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def run(tmp_path: Path) -> int:
    return main(["--examples", str(tmp_path / "examples"), "--schemas", str(tmp_path / "schemas")])


def test_missing_examples_dir_validates_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(tmp_path) == 0
    assert "validated 0 example file(s)" in capsys.readouterr().out


def test_valid_example_passes(tmp_path: Path) -> None:
    write(tmp_path / "schemas" / "run-record.schema.json", SCHEMA)
    write(tmp_path / "examples" / "run-record" / "ok.json", {"schema_version": "1.0.0"})
    assert run(tmp_path) == 0


def test_invalid_example_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "schemas" / "run-record.schema.json", SCHEMA)
    write(tmp_path / "examples" / "run-record" / "bad.json", {"schema_version": 1})
    assert run(tmp_path) == 1
    assert "schema_version: 1 is not of type 'string'" in capsys.readouterr().out


def test_official_schema_is_applied_too(tmp_path: Path) -> None:
    write(tmp_path / "schemas" / "report.schema.json", SCHEMA)
    write(
        tmp_path / "schemas" / "official" / "report.schema.json",
        {**SCHEMA, "required": ["schema_version", "uuid"]},
    )
    write(tmp_path / "examples" / "report" / "a.json", {"schema_version": "1.0.0"})
    assert run(tmp_path) == 1


def test_official_schema_alone_is_enough(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path / "schemas" / "official" / "vex.schema.json", SCHEMA)
    write(tmp_path / "examples" / "vex" / "ok.json", {"schema_version": "1.0.0"})
    write(tmp_path / "examples" / "vex" / "bad.json", {})
    assert run(tmp_path) == 1
    out = capsys.readouterr().out
    assert "bad.json vs" in out
    assert "ok.json vs" not in out
    assert "validated 2 example file(s); 1 problem(s)" in out


def test_format_without_schema_fails(tmp_path: Path) -> None:
    write(tmp_path / "examples" / "orphan" / "a.json", {})
    assert run(tmp_path) == 1


def test_stray_example_outside_a_format_dir_fails(tmp_path: Path) -> None:
    write(tmp_path / "examples" / "loose.json", {})
    assert run(tmp_path) == 1


def test_invalid_schema_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "schemas" / "x.schema.json", {"type": 12})
    write(tmp_path / "examples" / "x" / "a.json", {})
    assert run(tmp_path) == 1
    assert "is not a valid JSON Schema" in capsys.readouterr().out
