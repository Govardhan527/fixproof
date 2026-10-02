"""Version comparison per ecosystem, and vers containment (ADR-0007 item 2).

PyPI follows PEP 440 through `packaging` (SPEC_NOTES §9). The other ecosystems arrive in M3;
until then asking for their comparator is an error, so the SBOM method reports `error` and the
verdict is `unknown`, never `fixed`.

Containment follows vers-spec v1.2.0 (SPEC_NOTES §5): the constraints must be sorted and must
alternate as §5.4 requires; then the how-to-parse algorithm decides, with a range of one bound
evaluated by that bound's comparator as Clause 5.3.3.1 defines it.
"""

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


_COMPARATORS: dict[str, Comparator] = {"pypi": Pypi()}
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
