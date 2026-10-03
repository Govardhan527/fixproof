"""M5 integration: `fixproof gate` on real built images (ADR-0012, SUCCESS TEST step 3).

Uses the fixture images `scripts/demo_cluster.sh up` builds and pushes (FIXPROOF_IT_IMAGES): they
are in the local Docker daemon as `<registry>/fixproof/<name>:it` and in the registries by
digest. The gate reads them where a CI job would: the daemon, a `docker save` archive, an OCI
archive and the registry, with no registry credentials, and the live CISA KEV feed.
"""

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

CVE, LOG4SHELL = "CVE-2023-32681", "CVE-2021-44228"


@pytest.fixture(scope="module")
def images() -> dict[str, str]:
    path = os.environ.get("FIXPROOF_IT_IMAGES")
    if not path:
        if os.environ.get("CI"):
            pytest.fail("FIXPROOF_IT_IMAGES is not set; the integration setup did not run")
        pytest.skip("FIXPROOF_IT_IMAGES is not set (needs Docker and scripts/demo_cluster.sh)")
    data: dict[str, str] = json.loads(Path(path).read_text(encoding="utf-8"))
    return data


def built_tag(reference: str) -> str:
    """The tag build_fixtures.py gave the image in the local daemon."""
    return reference.split("@", 1)[0] + ":it"


def closed_yaml(tmp_path: Path, registries: list[str]) -> Path:
    path = tmp_path / "closed.yaml"
    path.write_text(
        f'schema_version: "1.0.0"\nregistries: [{", ".join(registries)}]\nclosed:\n'
        f"  - cve: {CVE}\n    packages:\n      - ecosystem: pypi\n        name: requests\n"
        '        fixed_version: "2.31.0"\n'
        f"  - cve: {LOG4SHELL}\n    packages:\n      - ecosystem: maven\n"
        "        namespace: org.apache.logging.log4j\n        name: log4j-core\n"
        '        fixed_version: "2.15.0"\n',
        encoding="utf-8",
    )
    return path


def gate(
    tmp_path: Path, image: str, registries: list[str], *flags: str
) -> subprocess.CompletedProcess[str]:
    no_credentials = tmp_path / "docker-config"
    no_credentials.mkdir(exist_ok=True)
    return subprocess.run(
        [
            sys.executable, "-c", "from fixproof.cli import main; main()",
            "gate", "--closed", str(closed_yaml(tmp_path, registries)), "--image", image, *flags,
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "DOCKER_CONFIG": str(no_credentials)},
        check=False,
        timeout=3600,
    )  # fmt: skip


def result_of(done: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert done.stdout, done.stderr
    result: dict[str, Any] = json.loads(done.stdout)
    from fixproof.validation import build_validator, load_schema, schema_errors

    assert schema_errors(build_validator(load_schema("gate-result.schema.json")), result) == []
    return result


def verdicts(result: dict[str, Any]) -> dict[str, str]:
    return {line["cve"]: line["verdict"] for line in result["results"]}


def test_a_built_image_that_brings_the_cve_back_is_blocked(
    tmp_path: Path, images: dict[str, str]
) -> None:
    done = gate(tmp_path, f"docker:{built_tag(images['requests-2.30.0'])}", [])
    assert done.returncode == 1, done.stderr
    assert "BLOCK: 1 of 2 closed CVEs are back in this image." in done.stdout
    assert f"still_affected  {CVE}  (not in CISA KEV)" in done.stdout
    assert f"fixed           {LOG4SHELL}  (in CISA KEV, due 2021-12-24)" in done.stdout


def test_a_built_image_with_the_fix_passes(tmp_path: Path, images: dict[str, str]) -> None:
    done = gate(tmp_path, f"docker:{built_tag(images['requests-2.31.0'])}", [], "--json")
    assert done.returncode == 0, done.stderr
    result = result_of(done)
    assert verdicts(result) == {CVE: "fixed", LOG4SHELL: "fixed"}
    kev = {line["cve"]: line["kev"] for line in result["results"]}
    assert kev[LOG4SHELL]["status"] == "listed"  # the live CISA feed
    assert kev[LOG4SHELL]["entry"]["date_added"] == "2021-12-10"
    assert kev[CVE]["status"] == "not_listed"
    assert kev[CVE]["feed"]["sha256"]
    assert kev[CVE]["feed"]["catalog_version"]


def docker_image_id(tag: str) -> str:
    done = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def test_a_docker_save_archive_is_gated_and_identified(
    tmp_path: Path, images: dict[str, str]
) -> None:
    tag = built_tag(images["requests-2.30.0"])
    archive = tmp_path / "app.tar"
    subprocess.run(["docker", "save", "--output", str(archive), tag], check=True)
    done = gate(tmp_path, f"docker-archive:{archive}", [], "--json")
    assert done.returncode == 1, done.stderr
    result = result_of(done)
    assert verdicts(result)[CVE] == "still_affected"
    image_id = docker_image_id(tag)
    assert {s["image_id"] for s in result["scanned"].values()} == {image_id}


def oci_archive_from_registry(reference: str, dest: Path) -> str:
    """An OCI image layout tar of `reference`, read from the open test registry over HTTP."""
    registry, rest = reference.split("/", 1)
    repository, digest = rest.split("@")
    base = f"http://{registry}/v2/{repository}"
    accept = (
        "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.v2+json"
    )
    request = urllib.request.Request(  # noqa: S310 (the test registry)
        f"{base}/manifests/{digest}", headers={"Accept": accept}
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 (test registry)
        manifest_bytes, media_type = response.read(), response.headers["Content-Type"]
    layout = dest.parent / "layout"
    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    (blobs / digest.split(":")[1]).write_bytes(manifest_bytes)
    manifest = json.loads(manifest_bytes)
    for blob in [manifest["config"], *manifest["layers"]]:
        with urllib.request.urlopen(f"{base}/blobs/{blob['digest']}", timeout=120) as response:  # noqa: S310
            data = response.read()
        assert "sha256:" + hashlib.sha256(data).hexdigest() == blob["digest"]
        (blobs / blob["digest"].split(":")[1]).write_bytes(data)
    (layout / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    index = {
        "schemaVersion": 2,
        "manifests": [{"mediaType": media_type, "digest": digest, "size": len(manifest_bytes)}],
    }
    (layout / "index.json").write_text(json.dumps(index))
    with tarfile.open(dest, "w") as tar:  # entries without "./": Syft refuses those
        for name in ("oci-layout", "index.json", "blobs"):
            tar.add(layout / name, arcname=name)
    return digest


def test_an_oci_archive_is_gated_and_names_its_manifest_digest(
    tmp_path: Path, images: dict[str, str]
) -> None:
    archive = tmp_path / "app-oci.tar"
    digest = oci_archive_from_registry(images["requests-2.30.0"], archive)
    done = gate(tmp_path, f"oci-archive:{archive}", [], "--json")
    assert done.returncode == 1, done.stderr
    result = result_of(done)
    assert verdicts(result)[CVE] == "still_affected"
    assert {s["manifest_digest"] for s in result["scanned"].values()} == {digest}


def test_registry_images_by_digest(tmp_path: Path, images: dict[str, str]) -> None:
    back = gate(tmp_path / "a", images["requests-2.30.0"], ["localhost:5001"])
    assert back.returncode == 1, back.stderr
    clean = gate(tmp_path / "b", images["requests-2.32.3"], ["localhost:5001"])
    assert clean.returncode == 0, clean.stderr
    assert "PASS: all 2 closed CVEs are proven gone from this image." in clean.stdout


def test_an_image_the_gate_cannot_read_fails_the_build_with_the_reason(
    tmp_path: Path, images: dict[str, str]
) -> None:
    """The password-protected registry, with no credentials: exit 2, never a pass."""
    done = gate(tmp_path, images["auth/requests-2.31.0"], ["localhost:5002"])
    assert done.returncode == 2, done.stderr
    assert "CANNOT PROVE: 2 of 2 closed CVEs could not be checked" in done.stdout
    assert "UNAUTHORIZED" in done.stdout


@pytest.fixture(autouse=True)
def _own_directories(tmp_path: Path) -> None:
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
