"""Validate every example output in examples/ against its JSON Schema.

Layout (ADR-0003):
    examples/<format>/*.json, *.yaml          examples of one format (inputs are YAML)
    <schemas>/<format>.schema.json            the project's schema for that format
    <schemas>/official/<format>.schema.json   the standard's own schema, where one exists

<schemas> defaults to src/fixproof/schemas, so the schemas ship inside the package and the CLI
can validate its own output at run time. Each format needs at least one of the two schemas;
every example is validated against each one present. Standard formats (OpenVEX, CycloneDX) have
only the official schema.
Exit codes: 0 all examples valid, 1 a schema is missing or invalid, or an example fails.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml
from jsonschema.exceptions import SchemaError

from fixproof.validation import build_validator, cyclonedx_errors, schema_errors

DEFAULT_SCHEMAS = Path("src/fixproof/schemas")
SUFFIXES = (".json", ".yaml")


def load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text) if path.suffix == ".yaml" else json.loads(text)


def problems_for(schema_path: Path, instance: Any) -> list[str]:
    try:
        validator = build_validator(load(schema_path))
    except SchemaError as exc:
        return [f"schema {schema_path} is not a valid JSON Schema: {exc.message}"]
    return schema_errors(validator, instance)


# Standards whose official schema needs companion schemas: validated through fixproof's own check
OFFICIAL_CHECKS = {"cyclonedx": ("official CycloneDX 1.6.2 schema", cyclonedx_errors)}


def validate(examples_dir: Path, schemas_dir: Path) -> tuple[int, list[str]]:
    """Return (number of example files checked, problems found)."""
    problems: list[str] = []
    checked = 0
    if not examples_dir.is_dir():
        return 0, problems
    for stray in sorted(p for p in examples_dir.iterdir() if p.suffix in SUFFIXES):
        problems.append(f"{stray}: example outputs must live in examples/<format>/")
    for format_dir in sorted(p for p in examples_dir.iterdir() if p.is_dir()):
        if format_dir.name in OFFICIAL_CHECKS:
            label, check = OFFICIAL_CHECKS[format_dir.name]
            for example in sorted(p for p in format_dir.iterdir() if p.suffix in SUFFIXES):
                checked += 1
                problems.extend(f"{example} vs {label}: {e}" for e in check(load(example)))
            continue
        own = schemas_dir / f"{format_dir.name}.schema.json"
        official = schemas_dir / "official" / f"{format_dir.name}.schema.json"
        present = [path for path in (own, official) if path.is_file()]
        if not present:
            problems.append(f"{format_dir}: no schema at {own} or {official}")
            continue
        for example in sorted(p for p in format_dir.iterdir() if p.suffix in SUFFIXES):
            checked += 1
            instance = load(example)
            for schema_path in present:
                for error in problems_for(schema_path, instance):
                    problems.append(f"{example} vs {schema_path}: {error}")
    return checked, problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate example outputs against schemas.")
    parser.add_argument("--examples", type=Path, default=Path("examples"))
    parser.add_argument("--schemas", type=Path, default=DEFAULT_SCHEMAS)
    args = parser.parse_args(argv)

    checked, problems = validate(args.examples, args.schemas)
    for problem in problems:
        print(problem)
    print(f"validated {checked} example file(s); {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
