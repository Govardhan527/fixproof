"""Debian versions (Debian Policy §5.6.12, SPEC_NOTES §6), with python-debian as an oracle."""

import random
import re
from itertools import pairwise
from pathlib import Path

import pytest
from debian.debian_support import version_compare

from fixproof.versions import VersionError, comparator_for

DPKG = comparator_for("deb")
SRC = Path(__file__).resolve().parents[1] / "src"

# Each list ascends. The first is the policy's own example ("~~, ~~a, ~, the empty part, a").
ASCENDING = [
    ["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a"],
    ["0.9", "1.0", "1.0.1", "1.1", "1.10", "2.0"],  # digit runs compare numerically
    ["2.36-9", "2.36-9+deb12u3", "2.36-9+deb12u13", "2.36-10"],  # the revision decides
    ["2.0", "2.0+really1.9-1", "2.1~rc1", "2.1"],
    ["9.9", "1:0.1", "1:0.2", "2:0.0"],  # the epoch outranks everything
    ["1.0-1", "1.0-1+b1", "1.0-2", "1.0a-1"],
    ["1.2.3~beta1-1", "1.2.3~rc1-1", "1.2.3-1"],  # tilde marks pre-releases
]
EQUAL = [("1.0", "1.0-0"), ("0:1.0", "1.0"), ("1.01", "1.1"), ("1.0-00", "1.0-0")]


@pytest.mark.parametrize("ascending", ASCENDING)
def test_policy_ordering(ascending: list[str]) -> None:
    for lower, higher in pairwise(ascending):
        assert DPKG.compare(lower, higher) == -1, (lower, higher)
        assert DPKG.compare(higher, lower) == 1, (higher, lower)


@pytest.mark.parametrize(("left", "right"), EQUAL)
def test_equal_versions(left: str, right: str) -> None:
    assert DPKG.compare(left, right) == 0


INVALID = [
    *("", "a:1.0", "1:", "1.0-", "1.0_1", "1.0 rc1", "1.0-r:1", "-1.0", "1.0-1-", "1.0!"),
    "\u0661:1.0",  # an Arabic-Indic digit is not an epoch
]


@pytest.mark.parametrize("version", INVALID)
def test_invalid_versions(version: str) -> None:
    with pytest.raises(VersionError, match="is not a Debian version"):
        DPKG.compare(version, "1.0")


def corpus(seed: int, size: int) -> list[str]:
    """Valid Debian versions built from the characters the policy allows."""
    rng = random.Random(seed)  # noqa: S311  # seeded test corpus, not security
    pieces = ["0", "1", "2", "9", "10", "01", "a", "b", "z", "A", "~", "~~", "+", ".", "~a"]
    versions = []
    while len(versions) < size:
        upstream = rng.choice("0123456789") + "".join(rng.choices(pieces, k=rng.randint(0, 4)))
        version = upstream
        if rng.random() < 0.5:
            version += (
                "-"
                + rng.choice(["1", "0", "2"])
                + "".join(rng.choices(pieces, k=rng.randint(0, 2)))
            )
        if rng.random() < 0.2:
            version = f"{rng.randint(0, 3)}:{version}"
        versions.append(version)
    return versions


def test_agrees_with_python_debian_on_a_seeded_corpus() -> None:
    versions = corpus(seed=20261002, size=400)
    rng = random.Random(7)  # noqa: S311  # seeded test corpus, not security
    pairs = [(rng.choice(versions), rng.choice(versions)) for _ in range(6000)]
    pairs += list(pairwise(sorted(set(versions))))
    for left, right in pairs:
        expected = version_compare(left, right)
        assert DPKG.compare(left, right) == (expected > 0) - (expected < 0), (left, right)


def test_the_shipped_code_never_imports_the_gpl_oracle() -> None:
    importer = re.compile(r"^\s*(from|import)\s+debian\b", re.MULTILINE)
    offenders = [p for p in SRC.rglob("*.py") if importer.search(p.read_text(encoding="utf-8"))]
    assert offenders == []
