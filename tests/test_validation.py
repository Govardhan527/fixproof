import copy
import hashlib
from importlib.resources import files
from typing import Any

import pytest
from jsonschema.exceptions import SchemaError

from fixproof.errors import OutputValidationError
from fixproof.validation import OPENVEX_SCHEMA, build_validator, check_openvex, openvex_errors

# ADR-0002 item 1: openvex/spec commit a68ccd19b15a9604d28ef66ebf33f27a772ba4ec.
OPENVEX_SCHEMA_SHA256 = "9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238"

VALID: dict[str, Any] = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://openvex.dev/docs/example/vex-0001",
    "author": "Example Vulnerability Management",
    "timestamp": "2026-10-02T08:00:00Z",
    "version": 1,
    "statements": [
        {
            "vulnerability": {"name": "CVE-2099-0001"},
            "products": [{"@id": "pkg:oci/app@sha256:" + "a" * 64}],
            "status": "fixed",
        }
    ],
}


def variant(path: list[str | int], value: Any) -> dict[str, Any]:
    """A copy of VALID with one field replaced (or removed when value is ...)."""
    document = copy.deepcopy(VALID)
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    if value is ...:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return document


def test_vendored_schema_is_the_pinned_release_file() -> None:
    data = (files("fixproof") / "schemas" / OPENVEX_SCHEMA).read_bytes()
    assert hashlib.sha256(data).hexdigest() == OPENVEX_SCHEMA_SHA256


def test_valid_document_passes() -> None:
    assert openvex_errors(VALID) == []
    check_openvex(VALID)


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        (["timestamp"], "2026-10-02 08:00", "is not a 'date-time'"),
        (["@id"], "not an iri", "is not a 'iri'"),
        (["@context"], "openvex", "is not a 'uri'"),
        (["statements", 0, "status"], "resolved", "is not one of"),
        (["statements", 0, "status"], "affected", "'action_statement' is a required property"),
        (["statements", 0, "status"], "not_affected", "is not valid under any of the given"),
        (["version"], 0, "less than the minimum of 1"),
        (["author"], ..., "'author' is a required property"),
    ],
)
def test_schema_and_format_violations_are_reported(
    path: list[str | int], value: Any, expected: str
) -> None:
    problems = openvex_errors(variant(path, value))
    assert any(expected in problem for problem in problems), problems


def test_check_openvex_raises_with_every_problem() -> None:
    with pytest.raises(OutputValidationError) as caught:
        check_openvex(variant(["timestamp"], "yesterday"))
    assert caught.value.problems == ["timestamp: 'yesterday' is not a 'date-time'"]
    assert "OpenVEX document fails its schema" in str(caught.value)


def test_build_validator_rejects_an_invalid_schema() -> None:
    with pytest.raises(SchemaError):
        build_validator({"$schema": "https://json-schema.org/draft/2020-12/schema", "type": 12})
