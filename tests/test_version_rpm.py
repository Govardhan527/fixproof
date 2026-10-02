"""RPM versions (rpm-version(7) at rpm 6.1.0, SPEC_NOTES §7).

Every ordering below is stated in the man page ("Comparing", "EXAMPLES" and "BUGS"). rpm's own
test vectors (tests/rpmvercmp.at) were checked during development, not copied (SPEC_NOTES §7).
"""

from itertools import pairwise

import pytest

from fixproof.versions import VersionError, comparator_for

RPM = comparator_for("rpm")

ASCENDING = [
    ["99", "123", "321"],
    ["1.0", "1.0.1", "1.0.2"],
    ["2.0", "2.60", "2.60.1-1", "3.0"],
    ["1.0", "1.0-1", "1.0-5", "1.0.1"],  # a release makes the EVR newer
    ["6.0-1", "4:6.0-1", "5:3.0-1", "5:3.1-1"],  # the epoch outranks everything
    ["0.99", "1.0~beta1", "1.0~beta2", "1.0"],  # tilde: pre-releases
    ["1.0", "2.0~beta1", "2.0~rc1", "2.0"],
    ["2.0", "2.0^20250611", "2.0.1"],  # caret: post-release snapshots
    ["2.0", "2.0^150825", "2.0.1"],
    ["2.0^git1", "2.0^git2", "2.0.1"],  # successive snapshots of one release
    ["0", "0.0"],  # more segments is newer
    ["1", "1.xyz", "1.0"],  # numeric segments are newer than alphabetic ones
    ["1c.f", "1.f"],  # BUGS: implicit segments compare one by one
]
EQUAL = [
    ("abc123", "abc0123"),
    ("abc123", "abc.123"),
    ("abc123", "abc.000123"),
    ("1.0", "1+0"),
    ("1.0", "1+.+0"),
    ("1.0", "0:1.0"),
]


@pytest.mark.parametrize("ascending", ASCENDING)
def test_man_page_ordering(ascending: list[str]) -> None:
    for lower, higher in pairwise(ascending):
        assert RPM.compare(lower, higher) == -1, (lower, higher)
        assert RPM.compare(higher, lower) == 1, (higher, lower)


@pytest.mark.parametrize(("left", "right"), EQUAL)
def test_equal_versions(left: str, right: str) -> None:
    assert RPM.compare(left, right) == 0
    assert RPM.compare(right, left) == 0


INVALID = [
    *("", "1:", ":1.0", "a:1.0", "1.0-", "1.0-1-2", "1.0 1", "1/0", "1.0-r@1"),
    "1.1.\u03b1",  # non-ASCII, which rpmbuild rejects (BUGS)
]


@pytest.mark.parametrize("version", INVALID)
def test_invalid_versions(version: str) -> None:
    with pytest.raises(VersionError, match="is not an RPM version"):
        RPM.compare(version, "1.0")


def test_real_distribution_versions() -> None:
    assert RPM.compare("3.0.7-24.el9", "3.0.7-25.el9") == -1
    assert RPM.compare("1:3.0.7-24.el9", "3.2.2-6.el9") == 1
    assert RPM.compare("3.0.7-24.el9_3", "3.0.7-24.el9") == 1
