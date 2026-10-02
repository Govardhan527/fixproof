"""Alpine apk versions (apk-tools v3.0.8 behaviour, SPEC_NOTES §8).

The orderings follow from the algorithm recorded in SPEC_NOTES §8. apk-tools' own
test/unit/version.data was checked during development, not copied (GPL; SPEC_NOTES §8).
"""

from itertools import pairwise

import pytest

from fixproof.versions import VersionError, comparator_for

APK = comparator_for("apk")

ASCENDING = [
    # Suffix order: alpha < beta < pre < rc < (none) < cvs < svn < git < hg < p.
    ["1.0_alpha", "1.0_alpha1", "1.0_beta2", "1.0_pre1", "1.0_rc1", "1.0", "1.0_cvs", "1.0_svn"],
    ["1.0_svn", "1.0_git", "1.0_hg", "1.0_p1", "1.0_p2"],
    ["1.0", "1.0-r1", "1.0_p1", "1.0.1"],  # a revision sorts below a post-release suffix
    ["2.0", "2.0a", "2.0b", "2.0.1"],  # one letter after the digits, then more digits
    ["1", "1.0", "1.0.0"],  # more digit groups is newer
    ["9", "10", "10.0", "100"],
    ["3.1.4-r0", "3.1.4-r1", "3.1.4-r10", "3.1.5-r0"],  # revision numbers compare numerically
    ["1.0_rc1-r5", "1.0-r0"],  # a pre-release with a revision is still below the release
]


@pytest.mark.parametrize("ascending", ASCENDING)
def test_ordering(ascending: list[str]) -> None:
    for lower, higher in pairwise(ascending):
        assert APK.compare(lower, higher) == -1, (lower, higher)
        assert APK.compare(higher, lower) == 1, (higher, lower)


@pytest.mark.parametrize(("left", "right"), [("1.0", "1.0"), ("1.0-r0", "1.0-r0"), ("0.0", "0.0")])
def test_equal_versions(left: str, right: str) -> None:
    assert APK.compare(left, right) == 0


@pytest.mark.parametrize(
    "version",
    ["", "a1", "1.0-", "1.0-1", "1.0_foo", "1.0ab", "1.0.a", "1.0-r1.2", "1.0-r1-r2", "1.0 r1"],
)
def test_invalid_versions(version: str) -> None:
    with pytest.raises(VersionError, match="is not an apk version"):
        APK.compare(version, "1.0")


@pytest.mark.parametrize(
    ("version", "reason"),
    [
        ("1.05", "leading-zero group"),
        ("1.0.012", "leading-zero group"),
        ("1.0~abc123", "commit hash"),
    ],
)
def test_forms_apk_2_and_3_order_differently_are_refused(version: str, reason: str) -> None:
    with pytest.raises(VersionError, match=reason):
        APK.compare(version, "1.0")


def test_a_lone_zero_group_is_not_a_leading_zero() -> None:
    assert APK.compare("1.0.1", "1.0.10") == -1
