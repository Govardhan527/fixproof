"""JSON Schema validation with format checking on.

jsonschema enforces `date-time`, `uri` and `iri` only when its optional format packages are
installed; fixproof depends on them (ADR-0006, SPEC_NOTES §1), and a test proves the checks run.
The official OpenVEX schema is the release file, byte for byte (ADR-0002 item 1).
"""

import json
from collections.abc import Mapping
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema.protocols import Validator
from jsonschema.validators import validator_for
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from fixproof.errors import OutputValidationError

OPENVEX_SCHEMA = "official/openvex.schema.json"
CYCLONEDX_SCHEMA = "official/cyclonedx/bom-1.6.schema.json"  # 1.6.2 (SPEC_NOTES §4)
# The two schemas bom-1.6 refers to, by the `$id` it uses for them (same tag)
CYCLONEDX_COMPANIONS = {
    "http://cyclonedx.org/schema/spdx.schema.json": "official/cyclonedx/spdx.schema.json",
    "http://cyclonedx.org/schema/jsf-0.82.schema.json": "official/cyclonedx/jsf-0.82.schema.json",
}


def build_validator(schema: dict[str, Any]) -> Validator:
    """A validator for `schema`'s own draft, with that draft's format checker.

    Raises `jsonschema.exceptions.SchemaError` if `schema` is not a valid schema.
    """
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    return validator_cls(schema, format_checker=validator_cls.FORMAT_CHECKER)


def schema_errors(validator: Validator, instance: Any) -> list[str]:
    """Every validation error as `path: message`, in a stable order."""
    errors = sorted(validator.iter_errors(instance), key=lambda e: [str(p) for p in e.path])
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors]


def load_schema(name: str) -> dict[str, Any]:
    """A schema shipped in the package, by its path under `fixproof/schemas/`."""
    schema: dict[str, Any] = json.loads(
        (files("fixproof") / "schemas" / name).read_text(encoding="utf-8")
    )
    return schema


@cache
def _openvex_validator() -> Validator:
    return build_validator(load_schema(OPENVEX_SCHEMA))


def openvex_errors(document: Mapping[str, Any]) -> list[str]:
    """Validate `document` against the official OpenVEX schema."""
    return schema_errors(_openvex_validator(), document)


def check_openvex(document: Mapping[str, Any]) -> None:
    """Raise `OutputValidationError` unless `document` is valid OpenVEX."""
    problems = openvex_errors(document)
    if problems:
        raise OutputValidationError("OpenVEX document", problems)


@cache
def _cyclonedx_validator() -> Validator:
    schema = load_schema(CYCLONEDX_SCHEMA)
    registry: Registry = Registry().with_resources(
        (uri, Resource.from_contents(load_schema(path), default_specification=DRAFT7))
        for uri, path in CYCLONEDX_COMPANIONS.items()
    )
    validator_cls = validator_for(schema)
    return validator_cls(schema, registry=registry, format_checker=validator_cls.FORMAT_CHECKER)


def cyclonedx_errors(document: Mapping[str, Any]) -> list[str]:
    """Validate `document` against the official CycloneDX 1.6.2 schema, offline."""
    return schema_errors(_cyclonedx_validator(), document)


def check_cyclonedx(document: Mapping[str, Any]) -> None:
    """Raise `OutputValidationError` unless `document` is valid CycloneDX 1.6."""
    problems = cyclonedx_errors(document)
    if problems:
        raise OutputValidationError("CycloneDX document", problems)
