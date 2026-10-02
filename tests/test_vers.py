"""vers syntax checks (vers-spec v1.2.0 §5.3, SPEC_NOTES §5)."""

import pytest

from fixproof.vers import check_vers


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("vers:deb/>=3.0.11-1~deb12u2|<3.1", [(">=", "3.0.11-1~deb12u2"), ("<", "3.1")]),
        ("vers:npm/1.2.3|>=2.0.0|<5.0.0", [("", "1.2.3"), (">=", "2.0.0"), ("<", "5.0.0")]),
        ("vers:pypi/>1.0|!=1.1", [(">", "1.0"), ("!=", "1.1")]),
        ("vers:maven/<=1.0%2Bfix", [("<=", "1.0%2Bfix")]),
        ("vers:rpm/>=1:3.0.7-24.el9", [(">=", "1:3.0.7-24.el9")]),
    ],
)
def test_valid_ranges_parse(value: str, expected: list[tuple[str, str]]) -> None:
    ecosystem = value.split(":")[1].split("/")[0]
    assert check_vers(value, ecosystem) == expected


@pytest.mark.parametrize(
    ("value", "expected_type", "reason"),
    [
        ("deb/>=1.0", "deb", "does not start with 'vers:'"),
        ("VERS:deb/>=1.0", "deb", "does not start with 'vers:'"),
        ("vers:Deb/>=1.0", "deb", "no valid lowercase type"),
        ("vers:deb>=1.0", "deb", "no valid lowercase type"),
        ("vers:npm/>=1.0", "deb", "expected 'deb'"),
        ("vers:deb/", "deb", "has no constraints"),
        ("vers:deb/*", "deb", "would mark every version fixed"),
        ("vers:deb/>= 1.0", "deb", "whitespace"),
        ("vers:deb/=1.0", "deb", "must not start with '='"),
        ("vers:deb/>=", "deb", "has no version"),
        ("vers:deb/>=1.0||<2", "deb", "has no version"),
        ("vers:deb/>=1.0|<1*", "deb", "must be encoded"),
        ("vers:deb/>=1.0%2", "deb", "invalid percent-escape"),
        ("vers:deb/>=1.0|<=1.0", "deb", "only once"),
    ],
)
def test_invalid_ranges_are_rejected(value: str, expected_type: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        check_vers(value, expected_type)


def test_a_trailing_newline_never_passes_as_a_type() -> None:
    with pytest.raises(ValueError, match="no valid lowercase type"):
        check_vers("vers:deb\n/>=1.0", "deb\n")
