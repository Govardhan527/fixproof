"""Syntax checks for vers range strings (vers-spec v1.2.0, SPEC_NOTES §5).

M1 checks only what needs no version comparison: the scheme, the type, the comparators, the
characters a version may hold and exact duplicates. The ordering rules of §5.4 compare versions,
so they arrive with the per-ecosystem comparators in M3.
"""

import re

_TYPE = re.compile(r"^[a-z][a-z0-9.-]*$")
_COMPARATORS = ("!=", "<=", ">=", "<", ">")
# §5.3.3.2: these characters must be percent-encoded inside a version.
_MUST_ENCODE = set("><=!*|")
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def split_constraint(constraint: str) -> tuple[str, str]:
    """Split one constraint into (comparator, version); the comparator may be ""."""
    for comparator in _COMPARATORS:
        if constraint.startswith(comparator):
            return comparator, constraint[len(comparator) :]
    return "", constraint


def check_vers(value: str, expected_type: str) -> list[tuple[str, str]]:
    """Return the constraints of `value` as (comparator, version); raise ValueError if invalid.

    `*` is rejected even though vers allows it: as a fixed range it would mark every version
    fixed, which no fix claim can prove.
    """
    scheme, colon, rest = value.partition(":")
    if scheme != "vers" or not colon:
        raise ValueError(f"{value!r} does not start with 'vers:'")
    vers_type, slash, constraints = rest.partition("/")
    if not slash or not _TYPE.fullmatch(vers_type):
        raise ValueError(f"{value!r} has no valid lowercase type before '/'")
    if vers_type != expected_type:
        raise ValueError(f"{value!r} has type {vers_type!r}; expected {expected_type!r}")
    if not constraints:
        raise ValueError(f"{value!r} has no constraints")
    if constraints == "*":
        raise ValueError(f"{value!r} would mark every version fixed")
    if any(not 0x21 <= ord(c) <= 0x7E for c in constraints):
        raise ValueError(f"{value!r} contains whitespace or non-printable characters")

    parsed = []
    for constraint in constraints.split("|"):
        if constraint.startswith("="):
            raise ValueError(f"{value!r}: a constraint must not start with '='")
        comparator, version = split_constraint(constraint)
        if not version:
            raise ValueError(f"{value!r}: constraint {constraint!r} has no version")
        if _MUST_ENCODE & set(version):
            raise ValueError(f"{value!r}: version {version!r} has characters that must be encoded")
        if _BAD_ESCAPE.search(version):
            raise ValueError(f"{value!r}: version {version!r} has an invalid percent-escape")
        parsed.append((comparator, version))
    versions = [version for _, version in parsed]
    if len(set(versions)) != len(versions):
        raise ValueError(f"{value!r}: each version may appear only once")
    return parsed
