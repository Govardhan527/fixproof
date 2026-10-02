"""The purl builder against the official purl-spec v1.0.1 vectors (SPEC_NOTES §5)."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from fixproof.purl import NAMESPACE_RULES, Identity, PurlType, build, identity

VECTORS = Path(__file__).parent / "fixtures" / "purl-spec"
# SHA-256 of each vendored tests/types/<type>-test.json at purl-spec v1.0.1 (SPEC_NOTES §5).
VECTOR_SHA256 = {
    "apk": "bdd1b7c1462136ad9f443636cc505e723f333fb3a99c4017458fcee21e700e6f",
    "deb": "9a5f89212d6a3c73906fa2576bd15c2bbac83d45439beb3c319a8c7b33e51e0e",
    "maven": "13ecbb6db32b88969945be148c52a744ad89732386f86945319d55e23a2878c1",
    "npm": "8e7d00358125a743e62163e8cc4875e7bfef4339d947a4c5e5cd8a25b3757db4",
    "oci": "a23376cc43bba896555178d7824f5736875038bbdacd77331ae71ca0e3687be4",
    "pypi": "da842b6563c74c52a4b3c2001fec370b9e857fdf0abf6c44bf30d2d243dbf07d",
    "rpm": "453383f8de2c7e28a8ba3cef6bcdfc1257437151b46225f1db17f9e7d680865b",
}


def vectors(test_type: str) -> list[Any]:
    cases = []
    for purl_type in sorted(VECTOR_SHA256):
        data = json.loads((VECTORS / f"{purl_type}-test.json").read_text(encoding="utf-8"))
        for number, test in enumerate(data["tests"]):
            if test["test_type"] == test_type and not test["expected_failure"]:
                cases.append(pytest.param(test, id=f"{purl_type}-{number}"))
    return cases


@pytest.mark.parametrize("purl_type", sorted(VECTOR_SHA256))
def test_vendored_vectors_are_the_pinned_files(purl_type: str) -> None:
    data = (VECTORS / f"{purl_type}-test.json").read_bytes()
    assert hashlib.sha256(data).hexdigest() == VECTOR_SHA256[purl_type]


def test_every_emitted_type_has_vectors() -> None:
    assert set(VECTOR_SHA256) == set(NAMESPACE_RULES)


@pytest.mark.parametrize("test", vectors("build"))
def test_official_build_vector(test: dict[str, Any]) -> None:
    given = test["input"]
    assert not given["subpath"]  # fixproof never emits subpaths
    built = build(
        given["type"],
        given["name"],
        namespace=given["namespace"],
        version=given["version"],
        qualifiers=given["qualifiers"],
    )
    assert not test["expected_failure"]
    assert built == test["expected_output"]


@pytest.mark.parametrize(
    ("purl_type", "name", "namespace", "version", "expected"),
    [
        ("pypi", "Django_Package", None, "1.0RC1", "pkg:pypi/django-package@1.0rc1"),
        ("deb", "Curl", "Debian", "7.50.3-1", "pkg:deb/debian/curl@7.50.3-1"),
        ("apk", "OpenSSL", "Alpine", "3.0.8-r0", "pkg:apk/alpine/openssl@3.0.8-r0"),
        ("rpm", "OpenSSL", "RedHat", "3.0.7-6.el9", "pkg:rpm/redhat/OpenSSL@3.0.7-6.el9"),
        ("maven", "Batik", "Org.Apache", "1.0-RC", "pkg:maven/Org.Apache/Batik@1.0-RC"),
        ("npm", "Animation", "@Angular", "1.0.0-Beta", "pkg:npm/%40Angular/Animation@1.0.0-Beta"),
        ("oci", "App", None, "SHA256:AB", "pkg:oci/app@sha256:ab"),
    ],
)
def test_case_insensitive_components_are_lowercased(
    purl_type: PurlType, name: str, namespace: str | None, version: str, expected: str
) -> None:
    assert build(purl_type, name, namespace=namespace, version=version) == expected


def test_namespace_segments_and_slashes() -> None:
    assert build("deb", "curl", namespace="/debian/") == "pkg:deb/debian/curl"
    assert build("npm", "x", namespace="a b/c") == "pkg:npm/a%20b/c/x"


def test_qualifiers_drop_empty_values_and_sort_lowercased_keys() -> None:
    built = build("oci", "app", version="sha256:aa", qualifiers={"Tag": "v1", "arch": ""})
    assert built == "pkg:oci/app@sha256:aa?tag=v1"


@pytest.mark.parametrize(
    ("purl_type", "namespace", "message"),
    [
        ("deb", None, "requires a namespace"),
        ("maven", "", "requires a namespace"),
        ("pypi", "acme", "must not have a namespace"),
        ("oci", "library", "must not have a namespace"),
    ],
)
def test_namespace_rules(purl_type: PurlType, namespace: str | None, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build(purl_type, "x", namespace=namespace)


def test_name_and_qualifier_key_are_checked() -> None:
    with pytest.raises(ValueError, match="requires a name"):
        build("npm", "/")
    with pytest.raises(ValueError, match="invalid purl qualifier key"):
        build("npm", "x", qualifiers={"1bad": "v"})


def test_a_trailing_newline_never_passes_as_a_key() -> None:
    with pytest.raises(ValueError, match="invalid purl qualifier key"):
        build("npm", "x", qualifiers={"tag\n": "v"})


@pytest.mark.parametrize("test", vectors("parse"))
def test_official_parse_vector_identity(test: dict[str, Any]) -> None:
    expected = test["expected_output"]
    assert identity(test["input"]) == Identity(
        expected["type"], expected["namespace"], expected["name"], expected["version"]
    )


@pytest.mark.parametrize(
    ("purl", "reason"),
    [
        ("pypi/requests@2.0", "is not a purl"),
        ("pkg:requests", "is not a purl"),
        ("pkg:pypi/", "has no name"),
        ("pkg:pypi/@1.0", "has no name"),
    ],
)
def test_identity_rejects_non_purls(purl: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        identity(purl)


def test_identity_of_a_syft_purl_drops_qualifiers() -> None:
    syft = "pkg:deb/debian/LibSSL3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"
    assert identity(syft) == Identity("deb", "debian", "libssl3", "3.0.11-1~deb12u2")
