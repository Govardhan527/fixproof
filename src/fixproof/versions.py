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


class Rpm:
    """RPM versions, `rpm-version(7)` at rpm 6.1.0 (SPEC_NOTES §7).

    `[epoch:]version[-release]`: the epoch is the leading digits before a `:` (0 when absent),
    the release follows the last `-`. Epoch, version and release are compared in turn; an EVR
    with a release ranks above the same EVR without one. Within a component, runs of letters
    and of digits are segments; `.`, `_` and `+` only separate them; `~` sorts a segment older
    and `^` newer, as rpm's own comparison does.
    """

    _COMPONENT = re.compile(r"^[A-Za-z0-9._+~^]+$")

    @classmethod
    def parse(cls, version: str) -> tuple[int, str, str | None]:
        epoch, colon, rest = version.partition(":")
        if not colon:
            epoch, rest = "0", version
        upstream, dash, release = rest.rpartition("-")
        if not dash:
            upstream, release = rest, ""
        if (
            not (epoch.isdigit() and epoch.isascii())
            or not cls._COMPONENT.match(upstream)
            or (dash and not cls._COMPONENT.match(release))
        ):
            raise VersionError(f"{version!r} is not an RPM version")
        return int(epoch), upstream, release if dash else None

    @staticmethod
    def vercmp(left: str, right: str) -> int:
        """rpm's segment comparison of one component."""
        if left == right:
            return 0
        i = j = 0
        while i < len(left) or j < len(right):
            while i < len(left) and not left[i].isalnum() and left[i] not in "~^":
                i += 1
            while j < len(right) and not right[j].isalnum() and right[j] not in "~^":
                j += 1
            a = left[i] if i < len(left) else ""
            b = right[j] if j < len(right) else ""
            if "~" in (a, b):  # sorts before everything, even the end
                if a != "~":
                    return 1
                if b != "~":
                    return -1
                i, j = i + 1, j + 1
                continue
            if "^" in (a, b):  # sorts after the end, before anything else
                if not a:
                    return -1
                if not b:
                    return 1
                if a != "^":
                    return 1
                if b != "^":
                    return -1
                i, j = i + 1, j + 1
                continue
            if not (a and b):
                break
            numeric = a.isdigit()
            same_kind = str.isdigit if numeric else str.isalpha
            end_i, end_j = i, j
            while end_i < len(left) and same_kind(left[end_i]):
                end_i += 1
            while end_j < len(right) and same_kind(right[end_j]):
                end_j += 1
            one, two = left[i:end_i], right[j:end_j]
            if not two:  # numeric segments are newer than alphabetic ones
                return 1 if numeric else -1
            if numeric:
                one, two = one.lstrip("0"), two.lstrip("0")
                if len(one) != len(two):
                    return _sign(len(one) - len(two))
            if one != two:
                return -1 if one < two else 1
            i, j = end_i, end_j
        if i >= len(left) and j >= len(right):
            return 0
        return -1 if i >= len(left) else 1

    def compare(self, left: str, right: str) -> int:
        (le, lv, lr), (re_, rv, rr) = self.parse(left), self.parse(right)
        if order := _sign(le - re_) or self.vercmp(lv, rv):
            return order
        if lr is None or rr is None:
            return (lr is not None) - (rr is not None)
        return self.vercmp(lr, rr)


class Apk:
    """Alpine versions, apk-tools v3.0.8 behaviour (SPEC_NOTES §8), re-implemented.

    `digits{.digits}{letter}{_suffix{number}}...{-rN}`, compared token by token. Two forms are
    refused because apk-tools 2 (Alpine 3.20 to 3.22) and 3 (3.23 onward) can order them
    differently: a digit group after `.` with a leading zero (`1.05`), and a `~hash`.
    """

    INITIAL, DIGIT, LETTER, SUFFIX, SUFFIX_NO, HASH, REVISION, END = range(8)
    # Suffix order; index 4 is "no suffix", so indexes below it are pre-releases.
    _SUFFIXES = ("alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg", "p")
    _NO_SUFFIX = 4
    _NAMED = frozenset(_SUFFIXES) - {""}
    _TOKEN = re.compile(r"\.([0-9]+)|([a-z])|_([a-z]*)|([0-9]+)|-r([0-9]+)")

    @classmethod
    def tokens(cls, version: str) -> list[tuple[int, int]]:
        """(kind, value) pairs; raises VersionError for an invalid or grey-zone version."""
        initial = re.match(r"[0-9]+", version)
        if initial is None or not version.isascii():
            raise VersionError(f"{version!r} is not an apk version")
        if "~" in version:
            raise VersionError(f"{version!r} has a commit hash, ordered differently by apk 2 and 3")
        tokens, position = [(cls.INITIAL, int(initial.group()))], initial.end()
        while position < len(version):
            match = cls._TOKEN.match(version, position)
            kind = tokens[-1][0]
            if match is None:
                raise VersionError(f"{version!r} is not an apk version")
            digits, letter, suffix, number, revision = match.groups()
            if digits is not None and kind <= cls.DIGIT:
                if len(digits) > 1 and digits.startswith("0"):
                    raise VersionError(
                        f"{version!r} has a leading-zero group, ordered differently by apk 2 and 3"
                    )
                tokens.append((cls.DIGIT, int(digits)))
            elif letter is not None and kind <= cls.DIGIT:
                tokens.append((cls.LETTER, ord(letter)))
            elif suffix is not None and kind <= cls.SUFFIX_NO and suffix in cls._NAMED:
                tokens.append((cls.SUFFIX, cls._SUFFIXES.index(suffix)))
            elif number is not None and kind == cls.SUFFIX:
                tokens.append((cls.SUFFIX_NO, int(number)))
            elif revision is not None and kind < cls.REVISION:
                tokens.append((cls.REVISION, int(revision)))
            else:
                raise VersionError(f"{version!r} is not an apk version")
            position = match.end()
        return [*tokens, (cls.END, 0)]

    def compare(self, left: str, right: str) -> int:
        a_tokens, b_tokens = self.tokens(left), self.tokens(right)
        index = 0  # both lists end with END, so the walk stops inside them
        while True:
            (a_kind, a_value), (b_kind, b_value) = a_tokens[index], b_tokens[index]
            if a_kind != b_kind or a_kind == self.END:
                break
            if a_value != b_value:
                return _sign(a_value - b_value)
            index += 1
        if a_kind == b_kind:
            return 0
        if a_kind == self.SUFFIX and a_value < self._NO_SUFFIX:
            return -1  # a pre-release suffix sorts below whatever the other version has
        if b_kind == self.SUFFIX and b_value < self._NO_SUFFIX:
            return 1
        return -1 if a_kind > b_kind else 1


_COMPARATORS: dict[str, Comparator] = {"apk": Apk(), "deb": Dpkg(), "pypi": Pypi(), "rpm": Rpm()}
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
