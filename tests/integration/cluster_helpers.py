"""What the cluster integration suites share: running fixproof as a user would, and checking
its evidence (tests/integration/test_cluster.py, test_minikube.py)."""

import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from fixproof import htmlreport
from fixproof.validation import (
    build_validator,
    check_cyclonedx,
    check_openvex,
    load_schema,
    schema_errors,
)

CVE = "CVE-2023-32681"
FIX = f"""\
schema_version: "1.0.0"
cve: {CVE}
packages:
  - ecosystem: pypi
    name: requests
    fixed_version: "2.31.0"
"""


def run_verify(
    tmp_path: Path,
    kubeconfig: str,
    context: str,
    namespaces: list[str],
    registries: list[str],
    *flags: str,
    images: tuple[str, ...] = (),
    docker_config: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """`fixproof verify` on one cluster context, with the reader's kubeconfig and, unless given,
    no registry credentials at all; `env` adds to the environment (a PATH, say)."""
    scope = f'schema_version: "1.0.0"\nregistries: [{", ".join(registries)}]\n'
    if images:
        scope += "images:\n" + "".join(f"  - {image}\n" for image in images)
    scope += f"clusters:\n  - context: {context}\n    namespaces: [{', '.join(namespaces)}]\n"
    (tmp_path / "fix.yaml").write_text(FIX, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(scope, encoding="utf-8")
    if docker_config is None:
        docker_config = tmp_path / "docker-config"
        docker_config.mkdir()
    return subprocess.run(
        [
            sys.executable, "-c", "from fixproof.cli import main; main()",
            "verify", "--cve", CVE, "--fix", str(tmp_path / "fix.yaml"),
            "--scope", str(tmp_path / "scope.yaml"), "--out", str(tmp_path / "out"),
            "--author", "fixproof integration tests", *flags,
        ],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "DOCKER_CONFIG": str(docker_config),
            "KUBECONFIG": kubeconfig,
            **(env or {}),
        },
        check=False,
        timeout=3600,
    )  # fmt: skip


def report_of(done: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """The `--json` summary, checked against its schema."""
    assert done.stdout, done.stderr
    report: dict[str, Any] = json.loads(done.stdout)
    validator = build_validator(load_schema("verify-summary.schema.json"))
    assert schema_errors(validator, report) == []
    return report


def by_owner(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["owner"].removeprefix("Deployment/"): item for item in report["assets"]}


def check_bundle(out: Path) -> dict[str, Any]:
    """The bundle and manifest validate, and every file matches its manifest entry."""
    bundle: dict[str, Any] = json.loads((out / "bundle.json").read_text())
    manifest = json.loads((out / "manifest.json").read_text())
    assert schema_errors(build_validator(load_schema("bundle.schema.json")), bundle) == []
    assert schema_errors(build_validator(load_schema("manifest.schema.json")), manifest) == []
    for entry in manifest["files"]:
        data = (out / entry["path"]).read_bytes()
        assert (hashlib.sha256(data).hexdigest(), len(data)) == (entry["sha256"], entry["size"])
    check_openvex(json.loads((out / "openvex.json").read_text()))
    check_cyclonedx(json.loads((out / "cyclonedx.json").read_text()))
    assert htmlreport.problems((out / "report.html").read_text(encoding="utf-8")) == []
    return bundle


def reader_token(kubeconfig: str) -> str:
    """The bearer token in the reader kubeconfig (scripts/reader_kubeconfig.sh)."""
    config = yaml.safe_load(Path(kubeconfig).read_text(encoding="utf-8"))
    token: str = config["users"][0]["user"]["token"]
    return token


def assert_nowhere(done: subprocess.CompletedProcess[str], out: Path, *secrets: str) -> None:
    """No secret appears in what fixproof printed or in any file it wrote."""
    written = [p.read_text(errors="replace") for p in out.rglob("*") if p.is_file()]
    for text in [done.stdout, done.stderr, *written]:
        for secret in secrets:
            assert secret not in text


def docker_hub_platforms(repository: str, digest: str) -> dict[str, str]:
    """`os/architecture[/variant]` -> manifest digest for a Docker Hub image index, read
    anonymously; attestation entries (platform unknown/unknown) are not platforms."""
    token_url = (
        "https://auth.docker.io/token?service=registry.docker.io"
        f"&scope=repository:{repository}:pull"
    )
    with urllib.request.urlopen(token_url, timeout=60) as response:  # noqa: S310 (fixed https)
        token = json.load(response)["token"]
    request = urllib.request.Request(
        f"https://registry-1.docker.io/v2/{repository}/manifests/{digest}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 (fixed https)
        index = json.load(response)
    platforms = {}
    for entry in index["manifests"]:
        platform = entry.get("platform") or {}
        if platform.get("os", "unknown") == "unknown":
            continue
        name = f"{platform['os']}/{platform['architecture']}"
        platforms[f"{name}/{platform['variant']}" if platform.get("variant") else name] = entry[
            "digest"
        ]
    return platforms


def kubectl(kubeconfig: str, *args: str) -> subprocess.CompletedProcess[str]:
    """The pinned kubectl the setup scripts put in `<work>/bin`, next to the kubeconfig."""
    return subprocess.run(
        [str(Path(kubeconfig).parent / "bin" / "kubectl"), "--kubeconfig", kubeconfig, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def kev_or_unavailable(kev: dict[str, Any], expected: str) -> bool:
    """The KEV status read from the live CISA feed during the run, if cisa.gov answered.

    The SUCCESS TEST evidence must not depend on cisa.gov: when the feed could not be read the
    run says so, with the reason, and the KEV values are left to the live suite. Returns whether
    the feed was available (and then its status must be `expected`).
    """
    if kev["status"] == "unavailable":
        assert kev["reason"], kev
        return False
    assert kev["status"] == expected, kev
    assert kev["feed"]["url"].startswith("https://www.cisa.gov/")
    return True
