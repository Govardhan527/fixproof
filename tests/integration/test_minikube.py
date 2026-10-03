"""Integration on a minikube node with Docker Engine or CRI-O (ADR-0010 Amendment 2, ADR-0011).

Needs FIXPROOF_IT_MINIKUBE_KUBECONFIG (the reader kubeconfig written by
`scripts/demo_minikube.sh up WORKDIR RUNTIME`) and FIXPROOF_IT_MINIKUBE_RUNTIME (`docker` or
`cri-o`), both set by the CI `integration-minikube` jobs; minikube's own default runtime,
containerd, is covered by the kind suite. The pods name their images the way users do
(`certbot/certbot:v2.6.0`, `python@sha256:...`). Locally these tests skip without the variables;
in CI they fail instead.
"""

import os
from pathlib import Path

import pytest
from cluster_helpers import (
    assert_nowhere,
    by_owner,
    check_bundle,
    docker_hub_platforms,
    kubectl,
    reader_token,
    report_of,
    run_verify,
)

import demo_workloads

pytestmark = pytest.mark.integration

RUNTIME_PREFIX = {"docker": "docker://", "cri-o": "cri-o://"}  # nodeInfo.containerRuntimeVersion


@pytest.fixture(scope="module")
def node() -> tuple[str, str, str]:
    """(reader kubeconfig, runtime, context and namespace)."""
    path, runtime = (
        os.environ.get(f"FIXPROOF_IT_MINIKUBE_{name}") for name in ("KUBECONFIG", "RUNTIME")
    )
    if not path or runtime not in demo_workloads.MINIKUBE_NAMESPACES:
        if os.environ.get("CI"):
            pytest.fail("FIXPROOF_IT_MINIKUBE_KUBECONFIG or _RUNTIME is not set; no minikube node")
        pytest.skip("needs a minikube node (scripts/demo_minikube.sh up)")
    return path, runtime, demo_workloads.MINIKUBE_NAMESPACES[runtime]


def image_ids(kubeconfig: str, namespace: str) -> list[str]:
    done = kubectl(
        kubeconfig, "get", "pods", "-n", namespace,
        "-o", "jsonpath={range .items[*]}{.status.containerStatuses[0].imageID}{'\\n'}{end}",
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    return done.stdout.split()


def test_the_node_runs_the_runtime_under_test(node: tuple[str, str, str]) -> None:
    """Checked with the setup's admin kubeconfig: the reader may not read nodes."""
    reader, runtime, _ = node
    admin = str(Path(reader).parent / "admin.kubeconfig")
    done = kubectl(
        admin, "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.containerRuntimeVersion}"
    )
    assert done.stdout.startswith(RUNTIME_PREFIX[runtime]), done.stdout


def test_the_image_ids_have_the_runtime_form(node: tuple[str, str, str]) -> None:
    """Docker Engine writes Docker's short names, CRI-O full names (SPEC_NOTES §12)."""
    kubeconfig, runtime, namespace = node
    ids = image_ids(kubeconfig, namespace)
    assert len(ids) == len(demo_workloads.MINIKUBE)
    for name in ("certbot-2-6-0", "python-official"):
        image, _, reported = demo_workloads.MINIKUBE[name]
        expected = f"docker-pullable://{image}" if runtime == "docker" else reported
        assert expected in ids, ids
    if runtime == "docker":
        assert any(i.startswith("docker://sha256:") for i in ids), ids


def test_workloads_get_the_expected_verdicts(tmp_path: Path, node: tuple[str, str, str]) -> None:
    kubeconfig, _, namespace = node
    done = run_verify(tmp_path, kubeconfig, namespace, [namespace], ["docker.io"], "--json")
    report = report_of(done)
    found = by_owner(report)
    assert set(found) == set(demo_workloads.MINIKUBE)
    for name, (_, verdict, reported) in demo_workloads.MINIKUBE.items():
        item = found[name]
        assert item["verdict"] == verdict, (name, item["reason"])
        if reported is not None:
            # The full name, whatever form the node used. CRI-O may report the linux/amd64
            # manifest of the index the pod named instead of the index (SPEC_NOTES §12): accept
            # that one only, as Docker Hub lists it for that index.
            repository, digest = reported.removeprefix("docker.io/").split("@")
            platform = docker_hub_platforms(repository, digest)["linux/amd64"]
            assert item["asset"] in {reported, f"docker.io/{repository}@{platform}"}, item
        assert item["workload"].startswith(f"{namespace}/{namespace}/{name}-")
    # The image loaded into the node is never read: it has no registry digest, or (CRI-O may name
    # it localhost/...@sha256 from its own manifest) its registry is outside the allowlist.
    local = found["local-only"]["reason"]
    assert "has no registry digest" in local or "registry not in scope: localhost" in local, local
    assert report["summary"] == {"fixed": 2, "still_affected": 2, "unknown": 1}
    assert done.returncode == 1
    check_bundle(tmp_path / "out")
    assert_nowhere(done, tmp_path / "out", reader_token(kubeconfig))


def test_the_reader_is_limited_on_this_node_too(tmp_path: Path, node: tuple[str, str, str]) -> None:
    kubeconfig, _, namespace = node
    done = run_verify(tmp_path, kubeconfig, namespace, ["kube-system"], ["docker.io"])
    assert done.returncode == 3
    assert f"{namespace}: list pods in kube-system: 403 Forbidden" in done.stderr
    secrets = kubectl(kubeconfig, "auth", "can-i", "get", "secrets", "-n", namespace)
    assert secrets.stdout.strip() == "no", secrets.stderr
