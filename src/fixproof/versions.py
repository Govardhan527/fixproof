"""Version comparison per ecosystem, and vers containment (ADR-0007 item 2).

PyPI follows PEP 440 through `packaging` (SPEC_NOTES §9); the others are written here from their
specifications (ADR-0009). An ecosystem without a comparator, or a version a comparator rejects,
is an error, so the SBOM method reports `error` and the verdict is `unknown`, never `fixed`.

Containment follows vers-spec v1.2.0 (SPEC_NOTES §5): the constraints must be sorted and must
alternate as §5.4 requires; then the how-to-parse algorithm decides, with a range of one bound
evaluated by that bound's comparator as Clause 5.3.3.1 defines it.
"""

import re
from itertools import pairwise
from typing import Protocol
from urllib.parse import unquote

from packaging.version import InvalidVersion, Version

from fixproof.inputs import FixPackage
from fixproof.vers import check_vers


class VersionError(ValueError):
    """A version or a range cannot be parsed or compared."""


class Comparator(Protocol):
    def compare(self, left: str, right: str) -> int:
        """Negative, zero or positive as `left` sorts before, equal to or after `right`."""
        ...


class Pypi:
    """PEP 440 ordering (SPEC_NOTES §9)."""

    @staticmethod
    def _parse(version: str) -> Version:
        try:
            return Version(version)
        except InvalidVersion as exc:
            raise VersionError(f"{version!r} is not a PEP 440 version") from exc

    def compare(self, left: str, right: str) -> int:
        a, b = self._parse(left), self._parse(right)
        return (a > b) - (a < b)


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


class Dpkg:
    """Debian versions, Debian Policy §5.6.12 (SPEC_NOTES §6).

    `[epoch:]upstream_version[-debian_revision]`, split at the first `:` and the last `-`. Parts
    are compared in alternating runs: non-digits lexically, with `~` before everything (even the
    end of the part) and letters before other characters; then digits numerically.
    """

    _UPSTREAM = re.compile(r"^[A-Za-z0-9.+~-]+$")
    _REVISION = re.compile(r"^[A-Za-z0-9.+~]+$")

    @classmethod
    def parse(cls, version: str) -> tuple[int, str, str]:
        epoch_text, colon, rest = version.partition(":")
        if not colon:
            epoch_text, rest = "0", version
        upstream, dash, revision = rest.rpartition("-")
        if not dash:
            upstream, revision = rest, "0"
        if (
            not epoch_text.isdigit()
            or not epoch_text.isascii()
            or not cls._UPSTREAM.match(upstream)
            or not cls._REVISION.match(revision)
        ):
            raise VersionError(f"{version!r} is not a Debian version")
        return int(epoch_text), upstream, revision

    @staticmethod
    def _weight(char: str) -> int:
        if char == "~":
            return -1
        return ord(char) if char.isalpha() else ord(char) + 256

    @classmethod
    def _lexical(cls, left: str, right: str) -> int:
        for index in range(max(len(left), len(right))):
            a = cls._weight(left[index]) if index < len(left) else 0  # end of part
            b = cls._weight(right[index]) if index < len(right) else 0
            if a != b:
                return _sign(a - b)
        return 0

    @staticmethod
    def _run(text: str) -> tuple[str, str, str]:
        """Split off the leading non-digit run and the digit run after it."""
        start = 0
        while start < len(text) and not text[start].isdigit():
            start += 1
        end = start
        while end < len(text) and text[end].isdigit():
            end += 1
        return text[:start], text[start:end], text[end:]

    @classmethod
    def _part(cls, left: str, right: str) -> int:
        while left or right:
            left_text, left_digits, left = cls._run(left)
            right_text, right_digits, right = cls._run(right)
            if order := cls._lexical(left_text, right_text):
                return order
            if order := _sign(int(left_digits or "0") - int(right_digits or "0")):
                return order
        return 0

    def compare(self, left: str, right: str) -> int:
        (le, lu, lr), (re_, ru, rr) = self.parse(left), self.parse(right)
        return _sign(le - re_) or self._part(lu, ru) or self._part(lr, rr)


_COMPARATORS: dict[str, Comparator] = {"deb": Dpkg(), "pypi": Pypi()}
_LOWER = ("<", "<=")
_UPPER = (">", ">=")


def comparator_for(ecosystem: str) -> Comparator:
    try:
        return _COMPARATORS[ecosystem]
    except KeyError:
        raise VersionError(f"fixproof cannot compare {ecosystem} versions yet") from None


def _satisfies(cmp: Comparator, version: str, comparator: str, bound: str) -> bool:
    order = cmp.compare(version, bound)
    return {
        "": order == 0,
        "!=": order != 0,
        "<": order < 0,
        "<=": order <= 0,
        ">": order > 0,
        ">=": order >= 0,
    }[comparator]


def _check_order(cmp: Comparator, constraints: list[tuple[str, str]], vers: str) -> None:
    """vers §5.4: sorted unique versions; equality and range comparators in a valid sequence."""
    for (_, lower), (_, higher) in pairwise(constraints):
        if cmp.compare(lower, higher) >= 0:
            raise VersionError(f"{vers}: constraints must be sorted by version, each once")
    kept = [op for op, _ in constraints if op != "!="]
    for current, following in pairwise(kept):
        if current == "" and following not in ("", ">", ">="):
            raise VersionError(f"{vers}: an equality constraint must be followed by =, > or >=")
    ranges = [op for op in kept if op != ""]
    for current, following in pairwise(ranges):
        if (current in _LOWER) == (following in _LOWER):
            raise VersionError(f"{vers}: range comparators must alternate between < and >")


def contains(vers: str, ecosystem: str, version: str) -> bool:
    """Whether `version` is inside the vers range. Raises VersionError when it cannot tell."""
    try:
        parsed = check_vers(vers, ecosystem)
    except ValueError as exc:
        raise VersionError(str(exc)) from exc
    cmp = comparator_for(ecosystem)
    constraints = [(op, unquote(bound)) for op, bound in parsed]
    _check_order(cmp, constraints, vers)

    if len(constraints) == 1:
        return _satisfies(cmp, version, *constraints[0])
    if any(op == "!=" and cmp.compare(version, b) == 0 for op, b in constraints):
        return False
    if any(op in ("", "<=", ">=") and cmp.compare(version, b) == 0 for op, b in constraints):
        return True
    ranges = [(op, bound) for op, bound in constraints if op not in ("", "!=")]
    if len(ranges) < 2:
        return bool(ranges) and _satisfies(cmp, version, *ranges[0])
    last = len(ranges) - 2
    for index, ((op, bound), (next_op, next_bound)) in enumerate(pairwise(ranges)):
        if index == 0 and op in _LOWER and cmp.compare(version, bound) < 0:
            return True
        if index == last and next_op in _UPPER and cmp.compare(version, next_bound) > 0:
            return True
        if (
            op in _UPPER
            and next_op in _LOWER
            and cmp.compare(version, bound) > 0
            and cmp.compare(version, next_bound) < 0
        ):
            return True
    return False


def is_fixed(package: FixPackage, version: str) -> bool:
    """Whether an installed `version` of `package` carries the fix (ADR-0005 item 1)."""
    cmp = comparator_for(package.ecosystem)
    if cmp.compare(version, package.fixed_version) >= 0:
        return True
    return package.fixed_vers is not None and contains(
        package.fixed_vers, package.ecosystem, version
    )
