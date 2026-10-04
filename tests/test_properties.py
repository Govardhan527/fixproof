"""Property-based tests (ADR-0013 item 3): generated inputs, fixed seed, no stored database.

The six comparators must be a total order on valid versions: every version equals itself,
swapping the arguments flips the sign, and the order is transitive. Valid versions come from each
ecosystem's grammar (SPEC_NOTES §6 to §11). The purl builder and parser must round-trip, and the
vers and purl parsers must reject bad input with ValueError only, never crash (vers has no
writer in fixproof, so it has no round-trip to test).
"""

import contextlib
import string

from hypothesis import given, settings
from hypothesis import strategies as st

from fixproof.purl import NAMESPACE_RULES, PurlType, _normal, build, identity
from fixproof.vers import check_vers
from fixproof.versions import VersionError, comparator_for

PROFILE = settings(derandomize=True, database=None, max_examples=300, deadline=None)
number = st.integers(min_value=0, max_value=99_999).map(str)


def _join(parts: list[str], sep: str = ".") -> str:
    return sep.join(parts)


def _alnum_from(first: str, rest: str, max_size: int = 8) -> st.SearchStrategy[str]:
    return st.tuples(st.sampled_from(first), st.text(alphabet=rest, max_size=max_size)).map("".join)


deb = st.builds(
    lambda epoch, upstream, revision: f"{epoch}{upstream}{revision}",
    st.one_of(st.just(""), number.map(lambda n: f"{n}:")),
    _alnum_from(string.digits, string.ascii_letters + string.digits + ".+~"),
    st.one_of(
        st.just(""),
        _alnum_from(string.digits, string.ascii_letters + string.digits + ".+~").map(
            lambda r: f"-{r}"
        ),
    ),
)
rpm = st.builds(
    lambda epoch, version, release: f"{epoch}{version}{release}",
    st.one_of(st.just(""), number.map(lambda n: f"{n}:")),
    _alnum_from(string.digits, string.ascii_letters + string.digits + "._+~^"),
    st.one_of(
        st.just(""),
        _alnum_from(string.digits, string.ascii_letters + string.digits + "._+~^").map(
            lambda r: f"-{r}"
        ),
    ),
)
apk_number = st.integers(min_value=0, max_value=9_999).map(str)
apk = st.builds(
    lambda first, more, letter, suffixes, release: (
        _join([first, *more]) + letter + "".join(suffixes) + release
    ),
    apk_number,
    st.lists(st.integers(min_value=1, max_value=999).map(str), max_size=3),
    st.one_of(st.just(""), st.sampled_from(string.ascii_lowercase)),
    st.lists(
        st.builds(
            lambda name, n: f"_{name}{n}",
            st.sampled_from(["alpha", "beta", "pre", "rc", "p"]),
            st.one_of(st.just(""), apk_number),
        ),
        max_size=2,
    ),
    st.one_of(st.just(""), apk_number.map(lambda n: f"-r{n}")),
)
semver_number = st.one_of(st.just("0"), st.integers(min_value=1, max_value=99_999).map(str))
semver_id = st.one_of(
    semver_number,
    _alnum_from(string.ascii_letters + "-", string.ascii_letters + string.digits + "-"),
)
npm = st.builds(
    lambda major, minor, patch, pre, build_: f"{major}.{minor}.{patch}{pre}{build_}",
    semver_number,
    semver_number,
    semver_number,
    st.one_of(
        st.just(""), st.lists(semver_id, min_size=1, max_size=3).map(lambda ids: "-" + _join(ids))
    ),
    st.one_of(
        st.just(""),
        st.lists(
            st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=5),
            min_size=1,
            max_size=2,
        ).map(lambda ids: "+" + _join(ids)),
    ),
)
maven_token = st.one_of(
    number,
    st.sampled_from(
        [
            "alpha",
            "beta",
            "milestone",
            "rc",
            "cr",
            "snapshot",
            "ga",
            "final",
            "release",
            "sp",
            "a",
            "b",
            "m",
            "foo",
        ]
    ),
)
maven = st.lists(st.tuples(st.sampled_from(".-"), maven_token), min_size=0, max_size=5).flatmap(
    lambda rest: number.map(lambda first: first + "".join(sep + token for sep, token in rest))
)
pypi = st.builds(
    lambda release, pre, post, dev: f"{_join(release)}{pre}{post}{dev}",
    st.lists(number, min_size=1, max_size=4),
    st.one_of(
        st.just(""),
        st.builds(lambda kind, n: f"{kind}{n}", st.sampled_from(["a", "b", "rc"]), number),
    ),
    st.one_of(st.just(""), number.map(lambda n: f".post{n}")),
    st.one_of(st.just(""), number.map(lambda n: f".dev{n}")),
)
GRAMMARS = {"deb": deb, "rpm": rpm, "apk": apk, "npm": npm, "maven": maven, "pypi": pypi}


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


def _check_total_order(ecosystem: str, a: str, b: str, c: str) -> None:
    cmp = comparator_for(ecosystem).compare
    assert cmp(a, a) == 0, a
    assert _sign(cmp(a, b)) == -_sign(cmp(b, a)), (a, b)
    if cmp(a, b) <= 0 and cmp(b, c) <= 0:
        assert cmp(a, c) <= 0, (a, b, c)


@PROFILE
@given(st.data())
def test_every_comparator_is_a_total_order_on_valid_versions(data: st.DataObject) -> None:
    ecosystem = data.draw(st.sampled_from(sorted(GRAMMARS)))
    grammar = GRAMMARS[ecosystem]
    a, b, c = data.draw(grammar), data.draw(grammar), data.draw(grammar)
    _check_total_order(ecosystem, a, b, c)


@PROFILE
@given(st.sampled_from(sorted(GRAMMARS)), st.text(max_size=30))
def test_comparators_reject_arbitrary_text_cleanly(ecosystem: str, text: str) -> None:
    """Any string either compares or raises VersionError: never another exception."""
    with contextlib.suppress(VersionError):
        comparator_for(ecosystem).compare(text, text)


name_text = st.text(
    alphabet=string.ascii_letters + string.digits + "-._~@:/% +", min_size=1, max_size=20
).filter(lambda s: s.strip("/") == s and "//" not in s)


@st.composite
def purl_parts(draw: st.DrawFn) -> tuple[PurlType, str, str | None, str | None]:
    purl_type: PurlType = draw(st.sampled_from(sorted(NAMESPACE_RULES)))
    rule = NAMESPACE_RULES[purl_type]
    if rule == "required":
        namespace: str | None = draw(name_text)
    elif rule == "optional":
        namespace = draw(st.one_of(st.none(), name_text))
    else:
        namespace = None
    return purl_type, draw(name_text), namespace, draw(st.one_of(st.none(), name_text))


@PROFILE
@given(purl_parts())
def test_purls_round_trip_for_every_type(
    parts: tuple[PurlType, str, str | None, str | None],
) -> None:
    """Every type fixproof writes reads back as written, after the type's own normalisation."""
    purl_type, name, namespace, version = parts
    parsed = identity(build(purl_type, name, namespace=namespace, version=version))
    assert (parsed.type, parsed.name, parsed.version) == (
        purl_type,
        _normal(purl_type, "name", name),
        _normal(purl_type, "version", version) if version is not None else None,
    )
    expected = (
        "/".join(_normal(purl_type, "namespace", s) for s in namespace.split("/") if s)
        if namespace
        else None
    )
    assert parsed.namespace == (expected or None)


@PROFILE
@given(st.text(max_size=80))
def test_the_purl_parser_rejects_bad_input_with_value_error_only(text: str) -> None:
    with contextlib.suppress(ValueError):
        identity(text)


@PROFILE
@given(st.text(max_size=60))
def test_the_vers_parser_rejects_bad_input_with_value_error_only(text: str) -> None:
    with contextlib.suppress(ValueError):
        check_vers(text, "pypi")
