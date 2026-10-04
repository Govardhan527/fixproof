from pathlib import Path

import pytest

from fixproof.errors import InputError
from fixproof.inputs import MAX_INPUT_BYTES, load_closed, load_fix, load_scope

DIGEST = "sha256:" + "0123456789abcdef" * 4
CVE = "CVE-2099-0001"  # synthetic: test data names no real CVE

FIX = f"""\
schema_version: "1.0.0"
cve: {CVE}
packages:
  - ecosystem: deb
    namespace: debian
    name: libdemo1
    fixed_version: "3.0.8-1"
    fixed_vers: "vers:deb/>=3.0.7-1~deb12u1|<3.0.8"
  - ecosystem: pypi
    name: demo-crypto
    fixed_version: "39.0.1"
"""

SCOPE = f"""\
schema_version: "1.0.0"
registries: [localhost:5001, registry.example.com]
images:
  - localhost:5001/fixproof/app@{DIGEST}
clusters:
  - context: kind-fixproof
    namespaces: [web, payments]
"""


def write(tmp_path: Path, text: str, name: str = "input.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def problems(error: pytest.ExceptionInfo[InputError]) -> str:
    return "\n".join(error.value.problems)


def test_fix_file_loads(tmp_path: Path) -> None:
    fix = load_fix(write(tmp_path, FIX), CVE)
    assert fix.cve == CVE
    assert [p.purl for p in fix.packages] == ["pkg:deb/debian/libdemo1", "pkg:pypi/demo-crypto"]
    assert fix.packages[0].fixed_vers == "vers:deb/>=3.0.7-1~deb12u1|<3.0.8"


def test_fix_file_must_be_for_the_requested_cve(tmp_path: Path) -> None:
    with pytest.raises(InputError) as caught:
        load_fix(write(tmp_path, FIX), "CVE-2099-0002")
    assert problems(caught) == f"cve: the file is for {CVE}, not CVE-2099-0002"


def test_requested_cve_must_be_a_cve_id(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="is not a CVE id"):
        load_fix(write(tmp_path, FIX), "2023-0286")


@pytest.mark.parametrize(
    ("replace", "by", "reason"),
    [
        ("    namespace: debian\n", "", "namespace is required for deb packages"),
        (
            "    name: demo-crypto\n",
            "    namespace: pypa\n    name: demo-crypto\n",
            "not allowed",
        ),
        ('fixed_version: "39.0.1"', "fixed_version: 39.1", "quote version strings in YAML"),
        ("vers:deb/>=", "vers:npm/>=", "expected 'deb'"),
        ("ecosystem: pypi", "ecosystem: gem", "Input should be"),
        ('schema_version: "1.0.0"', 'schema_version: "2.0.0"', "schema_version"),
        ("cve: CVE-2099-0001", "cve: CVE-23-1", "cve: String should match pattern"),
        ("  - ecosystem: pypi", "    color: blue\n  - ecosystem: pypi", "Extra inputs"),
    ],
)
def test_invalid_fix_files(tmp_path: Path, replace: str, by: str, reason: str) -> None:
    assert replace in FIX
    with pytest.raises(InputError) as caught:
        load_fix(write(tmp_path, FIX.replace(replace, by)), CVE)
    assert reason in problems(caught)
    assert str(tmp_path) in str(caught.value)


def test_duplicate_and_empty_package_lists(tmp_path: Path) -> None:
    pypi = FIX.split("  - ecosystem: pypi\n")[1]
    with pytest.raises(InputError, match="only once"):
        load_fix(write(tmp_path, FIX + "  - ecosystem: pypi\n" + pypi), CVE)
    with pytest.raises(InputError, match="at least 1 item"):
        load_fix(write(tmp_path, f'schema_version: "1.0.0"\ncve: {CVE}\npackages: []\n'), CVE)


def test_scope_file_loads(tmp_path: Path) -> None:
    scope = load_scope(write(tmp_path, SCOPE))
    assert [ref.reference for ref in scope.image_refs] == [f"localhost:5001/fixproof/app@{DIGEST}"]
    assert scope.clusters[0].namespaces == ("web", "payments")


@pytest.mark.parametrize(
    ("replace", "by", "reason"),
    [
        (
            "registries: [localhost:5001, registry.example.com]",
            "registries: [registry.example.com]",
            "from a registry not in registries",
        ),
        (
            "registries: [localhost:5001, registry.example.com]",
            "registries: [localhost:5001, localhost:5001]",
            "each registry may be listed only once",
        ),
        (
            "registries: [localhost:5001, registry.example.com]",
            "registries: [https://r.io]",
            "registries.0: String should match pattern",
        ),
        (f"localhost:5001/fixproof/app@{DIGEST}", f"fixproof/app@{DIGEST}", "no registry host"),
        ("    namespaces: [web, payments]", "    namespaces: [web, web]", "only once"),
        ("    namespaces: [web, payments]", "    namespaces: []", "at least 1 item"),
    ],
)
def test_invalid_scope_files(tmp_path: Path, replace: str, by: str, reason: str) -> None:
    assert replace in SCOPE
    with pytest.raises(InputError) as caught:
        load_scope(write(tmp_path, SCOPE.replace(replace, by)))
    assert reason in problems(caught)


def test_scope_needs_images_or_clusters_and_no_duplicates(tmp_path: Path) -> None:
    empty = 'schema_version: "1.0.0"\nregistries: [localhost:5001]\n'
    with pytest.raises(InputError, match="no images and no clusters"):
        load_scope(write(tmp_path, empty))
    image = f"localhost:5001/app@{DIGEST}"
    with pytest.raises(InputError, match="each image may be listed only once"):
        load_scope(write(tmp_path, empty + f"images: [{image}, {image}]\n"))
    cluster = "  - context: kind\n    namespaces: [web]\n"
    with pytest.raises(InputError, match="each cluster context may be listed only once"):
        load_scope(write(tmp_path, empty + "clusters:\n" + cluster + cluster))


def test_unreadable_and_malformed_files(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read the file"):
        load_scope(tmp_path / "missing.yaml")
    with pytest.raises(InputError, match="not valid YAML"):
        load_scope(write(tmp_path, "registries: [unclosed\n"))
    with pytest.raises(InputError, match="<root>: Input should be a valid dictionary"):
        load_fix(write(tmp_path, "- just\n- a list\n"), CVE)


def test_anchors_aliases_large_files_and_non_utf8_are_refused(tmp_path: Path) -> None:
    """ADR-0013 item 3: a "billion laughs" alias bomb, an oversized file and binary junk."""
    bomb = 'a: &a ["x","x"]\nb: &b [*a,*a]\nc: [*b,*b]\n'
    with pytest.raises(InputError, match=r"anchors and aliases are not allowed \(line 1\)"):
        load_scope(write(tmp_path, bomb))
    big = tmp_path / "big.yaml"
    big.write_bytes(b"# " + b"x" * MAX_INPUT_BYTES + b"\n")
    with pytest.raises(InputError, match=f"larger than {MAX_INPUT_BYTES} bytes"):
        load_scope(big)
    junk = tmp_path / "junk.yaml"
    junk.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(InputError, match="not UTF-8 text"):
        load_scope(junk)


TWO = "[linux/amd64, linux/arm64]"
PLATFORMS_SCOPE = f"""\
schema_version: "1.1.0"
registries: [localhost:5001]
images: [localhost:5001/fixproof/app@{DIGEST}]
platforms: [linux/amd64, linux/arm64]
"""


def test_scope_and_closed_files_may_list_platforms_from_version_1_1_0(tmp_path: Path) -> None:
    assert load_scope(write(tmp_path, PLATFORMS_SCOPE)).platforms == ("linux/amd64", "linux/arm64")
    assert load_scope(write(tmp_path, SCOPE)).platforms is None  # 1.0.0 files are unchanged
    closed = (
        'schema_version: "1.1.0"\nplatforms: [linux/arm/v7]\nclosed:\n  - cve: CVE-2023-32681\n'
        "    packages:\n      - {ecosystem: pypi, name: requests, fixed_version: '2.31.0'}\n"
    )
    assert load_closed(write(tmp_path, closed)).platforms == ("linux/arm/v7",)


@pytest.mark.parametrize(
    ("replace", "by", "reason"),
    [
        ('schema_version: "1.1.0"', 'schema_version: "1.0.0"', "platforms needs schema_version"),
        (TWO, "[linux/arm64, linux/arm64/v8]", "each platform may be listed only once"),
        (TWO, "[linux/arm, linux/arm/v7]", "each platform may be listed only once"),
        (TWO, "[]", "platforms, when given, names at least one platform"),
        (TWO, "[amd64]", "platforms.0: String should match pattern"),
        (TWO, "[Linux/AMD64]", "platforms.0: String should match pattern"),
        ('schema_version: "1.1.0"', 'schema_version: "1.2.0"', "schema_version"),
    ],
)  # fmt: skip
def test_invalid_platforms(tmp_path: Path, replace: str, by: str, reason: str) -> None:
    assert replace in PLATFORMS_SCOPE
    with pytest.raises(InputError) as caught:
        load_scope(write(tmp_path, PLATFORMS_SCOPE.replace(replace, by)))
    assert reason in problems(caught)
