"""Canonical Package URLs for the seven types fixproof emits (ADR-0005 item 5).

Rules from purl-spec v1.0.1 (SPEC_NOTES §5): component strings are UTF-8 and percent-encoded
except for `A-Z a-z 0-9 . - _ ~` and the colon, which is never encoded; the type and qualifier
keys are not encoded; qualifier pairs with an empty value are dropped and the rest are sorted.
Type-specific rules come from each type's definition file: which namespaces are required or
prohibited, and which components are case-insensitive (and therefore lowercased).
Checked against the official build vectors in tests/fixtures/purl-spec/.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote, unquote

PurlType = Literal["oci", "deb", "rpm", "apk", "pypi", "npm", "maven"]
NamespaceRule = Literal["required", "optional", "prohibited"]

NAMESPACE_RULES: dict[PurlType, NamespaceRule] = {
    "apk": "required",
    "deb": "required",
    "maven": "required",
    "npm": "optional",
    "oci": "prohibited",
    "pypi": "prohibited",
    "rpm": "required",
}
# Components each type definition marks `case_sensitive: false`.
_LOWERCASE: dict[str, frozenset[str]] = {
    "apk": frozenset({"namespace", "name"}),
    "deb": frozenset({"namespace", "name"}),
    "maven": frozenset(),
    "npm": frozenset(),
    "oci": frozenset({"name", "version"}),
    "pypi": frozenset({"name", "version"}),
    "rpm": frozenset({"namespace"}),
}
_KEY = re.compile(r"^[a-z][a-z0-9._-]*$")


def _encode(value: str) -> str:
    # quote() leaves only alphanumerics and "_.-~" unencoded; the colon is added (SPEC_NOTES §5).
    return quote(value, safe=":")


def _normal(purl_type: str, component: str, value: str) -> str:
    if component in _LOWERCASE.get(purl_type, frozenset()):
        value = value.lower()
    if purl_type == "pypi" and component == "name":
        value = value.replace("_", "-")
    return value


def build(
    purl_type: PurlType,
    name: str,
    *,
    namespace: str | None = None,
    version: str | None = None,
    qualifiers: Mapping[str, str] | None = None,
) -> str:
    """Return the canonical purl string. Raises ValueError for a component the type forbids."""
    rule = NAMESPACE_RULES[purl_type]
    segments = [s for s in (namespace or "").strip("/").split("/") if s]
    if rule == "required" and not segments:
        raise ValueError(f"a {purl_type} purl requires a namespace")
    if rule == "prohibited" and segments:
        raise ValueError(f"a {purl_type} purl must not have a namespace")
    name = name.strip("/")
    if not name:
        raise ValueError("a purl requires a name")

    parts = [f"pkg:{purl_type}/"]
    parts += [_encode(_normal(purl_type, "namespace", s)) + "/" for s in segments]
    parts.append(_encode(_normal(purl_type, "name", name)))
    if version:
        parts.append("@" + _encode(_normal(purl_type, "version", version)))
    pairs = []
    for key, value in (qualifiers or {}).items():
        if not _KEY.fullmatch(key.lower()):
            raise ValueError(f"invalid purl qualifier key {key!r}")
        if value:
            pairs.append(f"{key.lower()}={_encode(value)}")
    if pairs:
        parts.append("?" + "&".join(sorted(pairs)))
    return "".join(parts)


@dataclass(frozen=True)
class Identity:
    """The parts of a purl that identify a package, normalised as its type requires."""

    type: str
    namespace: str | None
    name: str
    version: str | None


def identity(purl: str) -> Identity:
    """Parse type, namespace, name and version (purl-spec how-to-parse, SPEC_NOTES §5).

    Qualifiers and subpath are dropped. Raises ValueError for a string that is not a purl.
    """
    remainder = purl.rsplit("#", 1)[0].rsplit("?", 1)[0]
    scheme, colon, remainder = remainder.partition(":")
    purl_type, slash, remainder = remainder.lstrip("/").partition("/")
    purl_type = purl_type.lower()
    if scheme.lower() != "pkg" or not colon or not slash or not purl_type:
        raise ValueError(f"{purl!r} is not a purl")
    # The version '@' is the last one in the final segment: the official vectors read an
    # unencoded '@' in an npm scope (pkg:npm/@babel/core) as part of the namespace.
    namespace_part, _, last = remainder.rstrip("/").rpartition("/")
    raw_name, at, raw_version = last.rpartition("@") if "@" in last else (last, "", "")
    version = _normal(purl_type, "version", unquote(raw_version)) if at and raw_version else None
    name = _normal(purl_type, "name", unquote(raw_name))
    if not name:
        raise ValueError(f"{purl!r} has no name")
    segments = [_normal(purl_type, "namespace", unquote(s)) for s in namespace_part.split("/") if s]
    return Identity(purl_type, "/".join(segments) or None, name, version)
