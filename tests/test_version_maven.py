"""Maven versions (SPEC_NOTES §11): the POM reference's examples and Maven's own test vectors.

tests/fixtures/maven/comparable-version.json holds the vectors of Apache Maven 3.9.16's
ComparableVersionTest (Apache-2.0, see NOTICE), including the expanded MNG-7644 loop.
"""

import json
from itertools import combinations
from pathlib import Path

import pytest

from fixproof.versions import VersionError, comparator_for

MAVEN = comparator_for("maven")
VECTORS = json.loads((Path(__file__).parent / "fixtures/maven/comparable-version.json").read_text())

# The POM reference's "End Result Examples" (SPEC_NOTES §11), except `1_0 = 1` (see below).
DOC_EXAMPLES = [
    ("1", "1.1", -1), ("1-snapshot", "1", -1), ("1", "1-sp", -1), ("1-foo2", "1-foo10", -1),
    ("1.foo", "1-foo", 0), ("1-foo", "1-1", -1), ("1-1", "1.1", -1), ("1.ga", "1", 0),
    ("1-ga", "1", 0), ("1-0", "1", 0), ("1.0", "1", 0), ("1-sp", "1-ga", 1),
    ("1-sp.1", "1-ga.1", 1), ("1-sp-1", "1-ga-1", -1), ("1-a1", "1-alpha-1", 0),
    ("1.0-alpha1", "1.0-ALPHA1", 0), ("1.7", "1.K", 1), ("5.zebra", "5.aardvark", 1),
    ("1." + chr(0x03B1), "1.b", 1),  # a Greek alpha sorts after b
]  # fmt: skip


@pytest.mark.parametrize(("left", "right", "expected"), DOC_EXAMPLES)
def test_pom_reference_examples(left: str, right: str, expected: int) -> None:
    assert MAVEN.compare(left, right) == expected
    assert MAVEN.compare(right, left) == -expected


@pytest.mark.parametrize("name", ["versions_qualifier_ascending", "versions_number_ascending"])
def test_maven_ordered_lists(name: str) -> None:
    for lower, higher in combinations(VECTORS[name], 2):
        assert MAVEN.compare(lower, higher) == -1, (lower, higher)
        assert MAVEN.compare(higher, lower) == 1, (higher, lower)


@pytest.mark.parametrize(("left", "right"), VECTORS["equal_pairs"])
def test_maven_equal_pairs(left: str, right: str) -> None:
    assert MAVEN.compare(left, right) == 0
    assert MAVEN.compare(right, left) == 0


@pytest.mark.parametrize(("lower", "higher"), VECTORS["ordered_pairs_lower_first"])
def test_maven_ordered_pairs(lower: str, higher: str) -> None:
    assert MAVEN.compare(lower, higher) == -1
    assert MAVEN.compare(higher, lower) == 1


def test_underscore_is_refused_because_the_sources_disagree() -> None:
    # The POM reference says `1_0 = 1`; Maven 3.9.16 and 4.0.0-rc-7 treat `_` as a character.
    with pytest.raises(VersionError, match="order differently"):
        MAVEN.compare("1_0", "1")


@pytest.mark.parametrize("version", ["", "1 .0", "1.0\n", "1.0\x00"])
def test_invalid_versions(version: str) -> None:
    with pytest.raises(VersionError, match="is not a Maven version"):
        MAVEN.compare(version, "1.0")


def test_real_artifact_versions() -> None:
    assert MAVEN.compare("2.14.1", "2.15.0") == -1  # log4j-core
    assert MAVEN.compare("2.17.0", "2.17.1") == -1
    assert MAVEN.compare("2.0-beta9", "2.0-rc1") == -1
    assert MAVEN.compare("2.0-rc2", "2.0") == -1
