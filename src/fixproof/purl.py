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
from typing import Literal
from urllib.parse import quote

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
_LOWERCASE: dict[PurlType, frozenset[str]] = {
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


def _normal(purl_type: PurlType, component: str, value: str) -> str:
    if component in _LOWERCASE[purl_type]:
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
