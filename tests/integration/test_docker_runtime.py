"""M4 integration on a Docker Engine node: minikube with cri-dockerd (ADR-0010 Amendment 2).

Needs FIXPROOF_IT_DOCKER_KUBECONFIG, the reader kubeconfig written by `scripts/demo_minikube.sh up`
in the CI `integration-docker-runtime` job (minikube with `--container-runtime=docker`; its
default is containerd). The node reports image IDs as `docker-pullable://<Docker's short
name>@sha256:...` or `docker://sha256:...`, and the pods name their images the way users do
(`certbot/certbot:v2.6.0`, `python@sha256:...`). Locally these tests skip without the variable;
in CI they fail instead.
"""

import os
from pathlib import Path

import pytest
from cluster_helpers import (
    assert_nowhere,
    by_owner,
    check_bundle,
    kubectl,
    reader_token,
    report_of,
    run_verify,
)

import demo_workloads

pytestmark = pytest.mark.integration

CONTEXT = "fixproof-docker"  # the minikube profile
NAMESPACE = demo_workloads.DOCKER_NAMESPACE


@pytest.fixture(scope="module")
def kubeconfig() -> str:
    path = os.environ.get("FIXPROOF_IT_DOCKER_KUBECONFIG")
    if not path:
        if os.environ.get("CI"):
            pytest.fail("FIXPROOF_IT_DOCKER_KUBECONFIG is not set; no minikube node")
        pytest.skip("needs the minikube node (scripts/demo_minikube.sh up)")
    return path


def test_the_node_really_runs_docker_engine(kubeconfig: str) -> None:
    """Every image ID has cri-dockerd's form, so the tests below exercise that path."""
    done = kubectl(
        kubeconfig, "get", "pods", "-n", NAMESPACE,
        "-o", "jsonpath={range .items[*]}{.status.containerStatuses[0].imageID}{'\\n'}{end}",
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    image_ids = done.stdout.split()
    assert len(image_ids) == len(demo_workloads.DOCKER)
    assert all(i.startswith(("docker-pullable://", "docker://")) for i in image_ids), image_ids
    assert any(i.startswith("docker://sha256:") for i in image_ids)  # the local image
    # Docker writes RepoDigests with its short names (SPEC_NOTES §12): this is what fixproof expands
    for name in ("certbot-2-6-0", "python-official"):
        image, _, _ = demo_workloads.DOCKER[name]
        assert f"docker-pullable://{image}" in image_ids, image_ids


def test_workloads_on_a_docker_engine_node(tmp_path: Path, kubeconfig: str) -> None:
    done = run_verify(tmp_path, kubeconfig, CONTEXT, [NAMESPACE], ["docker.io"], "--json")
    report = report_of(done)
    found = by_owner(report)
    assert set(found) == set(demo_workloads.DOCKER)
    for name, (_, verdict, reported) in demo_workloads.DOCKER.items():
        item = found[name]
        assert item["verdict"] == verdict, (name, item["reason"])
        assert item["asset"] == reported  # the short name expanded to registry/repository
        assert item["workload"].startswith(f"{CONTEXT}/{NAMESPACE}/{name}-")
    local = found["local-only"]["reason"]
    assert "has no registry digest" in local, local
    assert "docker://sha256:" in local
    assert report["summary"] == {"fixed": 2, "still_affected": 2, "unknown": 1}
    assert done.returncode == 1
    check_bundle(tmp_path / "out")
    assert_nowhere(done, tmp_path / "out", reader_token(kubeconfig))


def test_the_reader_is_limited_on_this_node_too(tmp_path: Path, kubeconfig: str) -> None:
    done = run_verify(tmp_path, kubeconfig, CONTEXT, ["kube-system"], ["docker.io"])
    assert done.returncode == 3
    assert f"{CONTEXT}: list pods in kube-system: 403 Forbidden" in done.stderr
    secrets = kubectl(kubeconfig, "auth", "can-i", "get", "secrets", "-n", NAMESPACE)
    assert secrets.stdout.strip() == "no", secrets.stderr
