"""Version comparison and vers containment (ADR-0007 item 2; SPEC_NOTES §5 and §9)."""

from itertools import pairwise

import pytest

from fixproof.inputs import FixPackage
from fixproof.versions import VersionError, comparator_for, contains, is_fixed

PYPI = comparator_for("pypi")

# SPEC_NOTES §9: the spec's own example ordering ("The following example covers many of the
# possible combinations"), verbatim and ascending.
PEP440_EXAMPLE = [
    "1.dev0",
    "1.0.dev456",
    "1.0a1",
    "1.0a2.dev456",
    "1.0a12.dev456",
    "1.0a12",
    "1.0b1.dev456",
    "1.0b2",
    "1.0b2.post345.dev456",
    "1.0b2.post345",
    "1.0rc1.dev456",
    "1.0rc1",
    "1.0",
    "1.0+abc.5",
    "1.0+abc.7",
    "1.0+5",
    "1.0.post456.dev34",
    "1.0.post456",
    "1.0.15",
    "1.1.dev1",
]
# Derived from the epoch rule in the same section: the epoch outranks every release segment.
EPOCH_ORDER = ["0.9", "1.0", "1.0.1", "1.1", "2.0", "1!0.1"]
PEP440_ORDER = [PEP440_EXAMPLE, EPOCH_ORDER]


@pytest.mark.parametrize("ascending", PEP440_ORDER)
def test_pep440_ordering(ascending: list[str]) -> None:
    for lower, higher in pairwise(ascending):
        assert PYPI.compare(lower, higher) < 0, (lower, higher)
        assert PYPI.compare(higher, lower) > 0, (higher, lower)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1.0", "1.0.0"),
        ("1.0c1", "1.0rc1"),
        ("1.0RC1", "1.0rc1"),
        ("v1.0", "1.0"),
        ("0!1.0", "1.0"),
    ],
)
def test_pep440_equal_after_normalisation(left: str, right: str) -> None:
    assert PYPI.compare(left, right) == 0


def test_invalid_versions_and_unsupported_ecosystems_are_errors() -> None:
    with pytest.raises(VersionError, match="not a PEP 440 version"):
        PYPI.compare("1.0", "not-a-version")
    for ecosystem in ("deb", "rpm", "apk", "npm", "maven"):
        with pytest.raises(VersionError, match=f"cannot compare {ecosystem} versions yet"):
            comparator_for(ecosystem)


@pytest.mark.parametrize(
    ("vers", "inside", "outside"),
    [
        ("vers:pypi/>=2.31.0", ["2.31.0", "2.32.3", "3.0"], ["2.30.0", "2.31.0rc1"]),
        ("vers:pypi/<2.0", ["1.9", "0.1"], ["2.0", "2.0.1"]),
        ("vers:pypi/>=1.2|<1.3", ["1.2", "1.2.9"], ["1.1", "1.3", "1.4"]),
        ("vers:pypi/>1.2|<=1.3", ["1.2.1", "1.3"], ["1.2", "1.3.1"]),
        ("vers:pypi/<1.0|>=2.0", ["0.9", "2.0", "2.1"], ["1.0", "1.5"]),
        ("vers:pypi/>=1.0|<1.1|>=2.0|<2.1", ["1.0.5", "2.0.5"], ["1.1", "1.9", "2.1"]),
        ("vers:pypi/1.5|>=2.0", ["1.5", "2.0", "3"], ["1.4", "1.6"]),
        ("vers:pypi/1.5", ["1.5", "1.5.0"], ["1.6"]),
        ("vers:pypi/!=1.5", ["1.4", "1.6"], ["1.5"]),
        ("vers:pypi/>=1.0|!=1.5|<2.0", ["1.0", "1.4", "1.9"], ["1.5", "2.0", "0.9"]),
        ("vers:pypi/>=1.0%2Bfix", ["1.0+fix", "1.1"], ["1.0"]),
    ],
)
def test_containment(vers: str, inside: list[str], outside: list[str]) -> None:
    for version in inside:
        assert contains(vers, "pypi", version), (vers, version)
    for version in outside:
        assert not contains(vers, "pypi", version), (vers, version)


@pytest.mark.parametrize(
    ("vers", "reason"),
    [
        ("vers:pypi/<2.0|>=1.0", "sorted by version"),
        ("vers:pypi/>=1.0|>=2.0", "alternate"),
        ("vers:pypi/<1.0|<2.0", "alternate"),
        ("vers:pypi/1.0|<2.0", "equality constraint"),
        ("vers:pypi/>=1.0|<1.0.0", "sorted by version"),
        ("vers:pypi/>=1.0|<bad", "not a PEP 440 version"),
    ],
)
def test_invalid_ranges_are_errors(vers: str, reason: str) -> None:
    with pytest.raises(VersionError, match=reason):
        contains(vers, "pypi", "1.5")


def package(**fields: str) -> FixPackage:
    return FixPackage.model_validate({"ecosystem": "pypi", "name": "requests", **fields})


def test_is_fixed_uses_the_fixed_version_and_the_backport_ranges() -> None:
    plain = package(fixed_version="2.31.0")
    assert [is_fixed(plain, v) for v in ("2.30.0", "2.31.0", "2.32.3")] == [False, True, True]
    backport = package(fixed_version="2.31.0", fixed_vers="vers:pypi/>=2.25.2|<2.26")
    assert [is_fixed(backport, v) for v in ("2.25.1", "2.25.2", "2.26.0", "2.31.0")] == [
        False,
        True,
        False,
        True,
    ]


def test_is_fixed_reports_versions_it_cannot_compare() -> None:
    with pytest.raises(VersionError):
        is_fixed(package(fixed_version="2.31.0"), "not.a.version!")
