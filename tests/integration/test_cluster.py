"""M4 integration: fixproof against the kind demo cluster (ADR-0010 item 9, SUCCESS TEST step 1).

Needs FIXPROOF_IT_IMAGES and FIXPROOF_IT_KUBECONFIG, both written by `scripts/demo_cluster.sh up`
in the CI `integration` job. fixproof runs with the read-only `fixproof-reader` token and no
registry credentials. Locally these tests skip without the variables; in CI they fail instead.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import demo_workloads
from fixproof.validation import check_openvex

pytestmark = pytest.mark.integration

CVE = "CVE-2023-32681"
CONTEXT = "kind-fixproof"
FIX = f"""\
schema_version: "1.0.0"
cve: {CVE}
packages:
  - ecosystem: pypi
    name: requests
    fixed_version: "2.31.0"
"""


@pytest.fixture(scope="module")
def setup() -> tuple[dict[str, str], str]:
    images, kubeconfig = (
        os.environ.get(f"FIXPROOF_IT_{name}") for name in ("IMAGES", "KUBECONFIG")
    )
    if not images or not kubeconfig:
        if os.environ.get("CI"):
            pytest.fail("FIXPROOF_IT_IMAGES or FIXPROOF_IT_KUBECONFIG is not set; no demo cluster")
        pytest.skip("needs the demo cluster (scripts/demo_cluster.sh up)")
    references: dict[str, str] = json.loads(Path(images).read_text(encoding="utf-8"))
    return references, kubeconfig


def verify(
    tmp_path: Path, kubeconfig: str, namespace: str, registries: list[str], *json_flag: str
) -> subprocess.CompletedProcess[str]:
    (tmp_path / "fix.yaml").write_text(FIX, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(
        f'schema_version: "1.0.0"\nregistries: [{", ".join(registries)}]\n'
        f"clusters:\n  - context: {CONTEXT}\n    namespaces: [{namespace}]\n",
        encoding="utf-8",
    )
    no_credentials = tmp_path / "docker-config"
    no_credentials.mkdir()
    return subprocess.run(
        [
            sys.executable, "-c", "from fixproof.cli import main; main()",
            "verify", "--cve", CVE, "--fix", str(tmp_path / "fix.yaml"),
            "--scope", str(tmp_path / "scope.yaml"), "--out", str(tmp_path / "out"),
            "--author", "fixproof integration tests", *json_flag,
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "DOCKER_CONFIG": str(no_credentials), "KUBECONFIG": kubeconfig},
        check=False,
        timeout=3600,
    )  # fmt: skip


def by_owner(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["owner"].removeprefix("Deployment/"): item for item in report["assets"]}


def test_success_test_six_workloads(tmp_path: Path, setup: tuple[dict[str, str], str]) -> None:
    images, kubeconfig = setup
    done = verify(
        tmp_path, kubeconfig, "fixproof-demo", ["localhost:5001", "localhost:5002"], "--json"
    )
    assert done.stdout, done.stderr
    report = json.loads(done.stdout)
    assert report["summary"] == {"fixed": 2, "still_affected": 3, "unknown": 1}
    found = by_owner(report)
    assert set(found) == set(demo_workloads.DEMO)
    for name, (fixture, verdict) in demo_workloads.DEMO.items():
        item = found[name]
        assert item["verdict"] == verdict, (name, item["reason"])
        assert item["asset"] == images[fixture]  # the digest the pod runs
        assert re.fullmatch(
            rf"{CONTEXT}/fixproof-demo/{name}-[a-z0-9]+-[a-z0-9]+/app", item["workload"]
        )
    unknown = found["partner-gateway"]["reason"]
    assert unknown.startswith("both methods failed"), unknown
    assert done.returncode == 1
    vex = json.loads((tmp_path / "out" / "openvex.json").read_text())
    check_openvex(vex)
    assert sorted(s["status"] for s in vex["statements"]) == [
        "affected", "affected", "affected", "fixed", "fixed", "under_investigation",
    ]  # fmt: skip


def test_human_output_names_pods_digests_and_the_reason(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    images, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, "fixproof-demo", ["localhost:5001", "localhost:5002"])
    assert done.returncode == 1, done.stderr
    orders = re.search(
        rf"still_affected  {CONTEXT}/fixproof-demo/(orders-\S+)/app  Deployment/orders\n\s+(\S+)",
        done.stdout,
    )
    assert orders, done.stdout
    assert orders.group(2) == images["requests-2.30.0"]
    assert "2 fixed, 3 still_affected, 1 unknown; evidence in" in done.stdout


def test_real_certbot_workloads(tmp_path: Path, setup: tuple[dict[str, str], str]) -> None:
    _, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, "fixproof-live", ["docker.io"], "--json")
    assert done.stdout, done.stderr
    found = by_owner(json.loads(done.stdout))
    for name, (image, verdict) in demo_workloads.LIVE.items():
        assert found[name]["verdict"] == verdict, (name, found[name]["reason"])
        assert found[name]["asset"] == image
    assert done.returncode == 1


def test_the_reader_cannot_list_other_namespaces(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    _, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, "kube-system", ["localhost:5001"])
    assert done.returncode == 3
    assert f"{CONTEXT}: list pods in kube-system: 403 Forbidden" in done.stderr
