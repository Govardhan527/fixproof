"""The demo cluster's workloads (ADR-0010 item 9), as Kubernetes manifests on stdout.

    demo_workloads.py --images fixture-images.json --pull-secret auth-registry > workloads.yaml

Namespace `fixproof-demo` runs the six SUCCESS TEST workloads from the fixture images
(scripts/build_fixtures.py): two fixed, three still affected, and one whose registry needs
credentials that fixproof is not given. Namespace `fixproof-live` runs two real certbot releases
from Docker Hub (ADR-0008 item 5). Namespace `fixproof-edge` holds the cases ADR-0010 must get
right on a real node: init containers, sidecars, two replicas sharing evidence, a bare pod, an
image that cannot be pulled, a pod that cannot be scheduled, an image side-loaded with
`kind load` (the node names it `docker.io/library/import-<date>`, an image that exists in no
registry), and an image referenced by tag. scripts/demo_cluster.sh
creates the namespaces, side-loads that image and adds an ephemeral container to the bare pod,
which fixproof must skip. Every container only sleeps and runs unprivileged. Images are pinned
by digest, except the side-loaded one and the two referenced by tag, as real Deployments often
are.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

DEMO_NAMESPACE, LIVE_NAMESPACE, EDGE_NAMESPACE = "fixproof-demo", "fixproof-live", "fixproof-edge"
# Deployment name -> (fixture image, verdict expected for CVE-2023-32681 fixed in requests 2.31.0)
DEMO: dict[str, tuple[str, str]] = {
    "orders": ("requests-2.30.0", "still_affected"),
    "billing": ("requests-2.25.1", "still_affected"),
    "reports": ("venv-only", "still_affected"),
    "payments": ("requests-2.31.0", "fixed"),
    "search": ("requests-2.32.3", "fixed"),
    "partner-gateway": ("auth/requests-2.31.0", "unknown"),  # its registry needs credentials
}
_CERTBOT = "docker.io/certbot/certbot@sha256:"
LIVE: dict[str, tuple[str, str]] = {  # the digests of tests/live/test_public_images.py
    "certbot-2-6-0": (
        _CERTBOT + "92092d214a4eb75d049720d04f7acc50b40ea226d77736bce6a6bf43981b6e86",
        "still_affected",  # certbot v2.6.0 pins requests 2.28.2
    ),
    "certbot-2-7-0": (
        _CERTBOT + "68e0f51ce9037d3b022d446772277beb1e9c0fe801e75fbf87db105ab165ad54",
        "fixed",  # certbot v2.7.0 pins requests 2.31.0
    ),
    # As most real Deployments are written: a Docker Hub short name and a tag, not a digest.
    # Tag v2.6.0 pointed at the digest above on 2026-10-03 (SPEC_NOTES §19).
    "certbot-by-tag": ("certbot/certbot:v2.6.0", "still_affected"),
}
SIDE_LOADED = "fixproof-side-loaded:it"  # built and loaded with `kind load` by demo_cluster.sh
DEBUG_FIXTURE = "requests-2.25.1"  # the ephemeral container demo_cluster.sh adds to bare-pod
# Namespace fixproof-edge: (pod name prefix, container) -> (verdict, text the reason contains)
EDGE: dict[tuple[str, str], tuple[str, str]] = {
    ("bare-pod", "app"): ("still_affected", "requests 2.25.1"),
    ("pull-backoff-", "app"): ("unknown", "the container has not started ("),
    # The node reports a side-loaded image as docker.io/library/import-<date>@sha256:... (seen in
    # CI 37117704337), a name no registry holds: outside the allowlist here, so never read.
    ("side-loaded-", "app"): ("unknown", "registry not in scope: docker.io"),
    ("two-replicas-", "setup"): ("fixed", "requests 2.32.3"),
    ("two-replicas-", "app"): ("still_affected", "requests 2.30.0"),
    ("two-replicas-", "sidecar"): ("fixed", "both methods agree"),
    ("by-tag-", "app"): ("still_affected", "requests 2.30.0"),
    ("unschedulable-", "app"): ("unknown", "no status yet, pod Pending"),
}


DOCKER_NAMESPACE = "fixproof-docker"  # on the minikube node (scripts/demo_minikube.sh)
DOCKER_LOCAL = "fixproof-docker-local:it"  # built and loaded with `minikube image load`
_CERTBOT_2_6_0 = LIVE["certbot-2-6-0"][0].split("@")[1]
_CERTBOT_2_7_0 = LIVE["certbot-2-7-0"][0].split("@")[1]
_PYTHON_SLIM = "sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3"
# Namespace fixproof-docker, on a node running Docker Engine through cri-dockerd (ADR-0010
# Amendment 2), written with Docker's short names as users write them. Deployment -> (image in
# the pod spec, expected verdict, the full reference fixproof must report, or None)
DOCKER: dict[str, tuple[str, str, str | None]] = {
    "certbot-2-6-0": (
        f"certbot/certbot@{_CERTBOT_2_6_0}",
        "still_affected",
        f"docker.io/certbot/certbot@{_CERTBOT_2_6_0}",
    ),
    "certbot-2-7-0": (
        f"certbot/certbot@{_CERTBOT_2_7_0}",
        "fixed",
        f"docker.io/certbot/certbot@{_CERTBOT_2_7_0}",
    ),
    "certbot-by-tag": (
        "certbot/certbot:v2.6.0",
        "still_affected",
        f"docker.io/certbot/certbot@{_CERTBOT_2_6_0}",
    ),
    # python:3.12-slim-bookworm (tests/live): an official image, so Docker writes `python@...`
    # and fixproof must expand it to docker.io/library/python; it has no requests: fixed
    "python-official": (
        f"python@{_PYTHON_SLIM}",
        "fixed",
        f"docker.io/library/python@{_PYTHON_SLIM}",
    ),
    "local-only": (DOCKER_LOCAL, "unknown", None),  # no repository digest: docker://sha256:...
}


def container(
    name: str, image: str, command: Sequence[str] = ("sleep", "86400"), pull: str | None = None
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "name": name,
        "image": image,
        "command": list(command),
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "10m", "memory": "16Mi"},
            "limits": {"memory": "64Mi"},
        },
    }
    if pull:
        spec["imagePullPolicy"] = pull
    return spec


def pod_spec(
    containers: list[dict[str, Any]],
    init: list[dict[str, Any]] | None = None,
    pull_secret: str | None = None,
    node_selector: dict[str, str] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": containers,
    }
    if init:
        spec["initContainers"] = init
    if pull_secret:
        spec["imagePullSecrets"] = [{"name": pull_secret}]
    if node_selector:
        spec["nodeSelector"] = node_selector
    return spec


def _labels(name: str) -> dict[str, str]:
    return {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "fixproof-demo"}


def deployment(
    name: str, namespace: str, spec: dict[str, Any], replicas: int = 1
) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": _labels(name)},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "template": {"metadata": {"labels": _labels(name)}, "spec": spec},
        },
    }


def bare_pod(name: str, namespace: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": _labels(name)},
        "spec": spec,
    }


def manifests(images: dict[str, str], pull_secret: str) -> list[dict[str, Any]]:
    documents = []
    for name, (fixture, _) in DEMO.items():
        secret = pull_secret if fixture.startswith("auth/") else None
        spec = pod_spec([container("app", images[fixture])], pull_secret=secret)
        documents.append(deployment(name, DEMO_NAMESPACE, spec))
    for name, (image, _) in LIVE.items():
        documents.append(deployment(name, LIVE_NAMESPACE, pod_spec([container("app", image)])))
    registry = images["requests-2.30.0"].split("/", 1)[0]
    missing = f"{registry}/fixproof/missing@sha256:{'0' * 64}"  # no such image: never pulls
    edge = [
        bare_pod(
            "bare-pod", EDGE_NAMESPACE, pod_spec([container("app", images["requests-2.25.1"])])
        ),
        deployment(
            "two-replicas",
            EDGE_NAMESPACE,
            pod_spec(
                [
                    container("app", images["requests-2.30.0"]),
                    container("sidecar", images["no-requests"]),
                ],
                init=[container("setup", images["requests-2.32.3"], command=("true",))],
            ),
            replicas=2,
        ),
        deployment("pull-backoff", EDGE_NAMESPACE, pod_spec([container("app", missing)])),
        deployment(
            "unschedulable",
            EDGE_NAMESPACE,
            pod_spec(
                [container("app", images["requests-2.31.0"])],
                node_selector={"fixproof.example/no-such-node": "true"},
            ),
        ),
        deployment(  # by tag, as most Deployments are written; build_fixtures.py pushes `:it`
            "by-tag",
            EDGE_NAMESPACE,
            pod_spec([container("app", f"{registry}/fixproof/requests-2.30.0:it")]),
        ),
        deployment(
            "side-loaded",
            EDGE_NAMESPACE,
            pod_spec([container("app", SIDE_LOADED, pull="Never")]),
        ),
    ]
    return documents + edge


def docker_manifests() -> list[dict[str, Any]]:
    """The minikube node's workloads (namespace fixproof-docker)."""
    return [
        deployment(
            name,
            DOCKER_NAMESPACE,
            pod_spec([container("app", image, pull="Never" if image == DOCKER_LOCAL else None)]),
        )
        for name, (image, _, _) in DOCKER.items()
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the demo clusters' workloads.")
    parser.add_argument("--images", type=Path, help="build_fixtures.py output (kind cluster)")
    parser.add_argument("--pull-secret", help="secret for the auth registry (kind cluster)")
    parser.add_argument("--docker", action="store_true", help="the minikube node's workloads")
    args = parser.parse_args(argv)
    if args.docker:
        documents = docker_manifests()
    elif args.images and args.pull_secret:
        images = json.loads(args.images.read_text(encoding="utf-8"))
        documents = manifests(images, args.pull_secret)
    else:
        parser.error("give --docker, or --images and --pull-secret")
    sys.stdout.write(yaml.safe_dump_all(documents, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
