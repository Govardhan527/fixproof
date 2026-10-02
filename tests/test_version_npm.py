"""npm versions: SemVer 2.0.0 precedence (SPEC_NOTES §10).

The first ordering is semver.org §11's own example; node-semver's strict comparison and equality
fixtures (ISC) are vendored in tests/fixtures/node-semver/.
"""

import json
from itertools import pairwise
from pathlib import Path

import pytest

from fixproof.versions import VersionError, comparator_for

NPM = comparator_for("npm")
FIXTURES = Path(__file__).parent / "fixtures" / "node-semver"

ASCENDING = [
    # semver.org §11.4, verbatim.
    ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
     "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"],
    ["1.0.0", "2.0.0", "2.1.0", "2.1.1"],  # §11.2
    ["1.0.0-9", "1.0.0-10", "1.0.0-a"],  # numeric identifiers numerically, below alphanumerics
]  # fmt: skip


@pytest.mark.parametrize("ascending", ASCENDING)
def test_semver_precedence(ascending: list[str]) -> None:
    for lower, higher in pairwise(ascending):
        assert NPM.compare(lower, higher) == -1, (lower, higher)
        assert NPM.compare(higher, lower) == 1, (higher, lower)


def fixture(name: str) -> list[list[str]]:
    pairs: list[list[str]] = json.loads((FIXTURES / f"{name}.json").read_text())["pairs"]
    return pairs


@pytest.mark.parametrize(("greater", "lesser"), fixture("comparisons"))
def test_node_semver_comparisons(greater: str, lesser: str) -> None:
    assert NPM.compare(greater, lesser) == 1
    assert NPM.compare(lesser, greater) == -1


@pytest.mark.parametrize(("left", "right"), fixture("equality"))
def test_node_semver_equality_ignores_build_metadata(left: str, right: str) -> None:
    assert NPM.compare(left, right) == 0


@pytest.mark.parametrize(
    "version",
    [
        "",
        "1.0",
        "1.0.0.0",
        "01.0.0",
        "1.0.0-01",
        "1.0.0-",
        "1.0.0+",
        "v1.0.0",
        "1.0.0-a..b",
        chr(0x0661) + ".0.0",
    ],
)
def test_invalid_versions(version: str) -> None:
    with pytest.raises(VersionError, match=r"is not a SemVer 2\.0\.0 version"):
        NPM.compare(version, "1.0.0")
