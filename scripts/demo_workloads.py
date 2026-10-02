"""The demo cluster's workloads (ADR-0010 item 9), as Kubernetes manifests on stdout.

    demo_workloads.py --images fixture-images.json --pull-secret auth-registry > workloads.yaml

Namespace `fixproof-demo` runs the six SUCCESS TEST workloads from the fixture images
(scripts/build_fixtures.py): two fixed, three still affected, and one whose registry needs
credentials that fixproof is not given. Namespace `fixproof-live` runs two real certbot releases
from Docker Hub (ADR-0008 item 5). Each Deployment pins its image by digest, only sleeps, and
runs unprivileged. The namespaces themselves are created by scripts/demo_cluster.sh.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

DEMO_NAMESPACE, LIVE_NAMESPACE = "fixproof-demo", "fixproof-live"
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
}


def deployment(
    name: str, namespace: str, image: str, pull_secret: str | None = None
) -> dict[str, Any]:
    labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "fixproof-demo"}
    pod: dict[str, Any] = {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": "app",
                "image": image,
                "command": ["sleep", "86400"],
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
        ],
    }
    if pull_secret:
        pod["imagePullSecrets"] = [{"name": pull_secret}]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "template": {"metadata": {"labels": labels}, "spec": pod},
        },
    }


def manifests(images: dict[str, str], pull_secret: str) -> list[dict[str, Any]]:
    documents = []
    for name, (fixture, _) in DEMO.items():
        secret = pull_secret if fixture.startswith("auth/") else None
        documents.append(deployment(name, DEMO_NAMESPACE, images[fixture], secret))
    for name, (image, _) in LIVE.items():
        documents.append(deployment(name, LIVE_NAMESPACE, image))
    return documents


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the demo cluster's Deployments.")
    parser.add_argument("--images", type=Path, required=True, help="build_fixtures.py output")
    parser.add_argument("--pull-secret", required=True, help="secret for the auth registry")
    args = parser.parse_args(argv)
    images = json.loads(args.images.read_text(encoding="utf-8"))
    sys.stdout.write(yaml.safe_dump_all(manifests(images, args.pull_secret), sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
