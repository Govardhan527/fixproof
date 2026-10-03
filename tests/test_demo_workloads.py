"""The demo cluster's workloads: the SUCCESS TEST six, the live two, and the edge cases."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

import demo_workloads
from fixproof.model import ImageRef

DIGEST = "@sha256:" + "ab" * 32
IMAGES = {
    name: f"localhost:5001/fixproof/{name}{DIGEST}"
    for name in (
        "requests-2.30.0",
        "requests-2.25.1",
        "venv-only",
        "requests-2.31.0",
        "requests-2.32.3",
        "no-requests",
    )
} | {"auth/requests-2.31.0": f"localhost:5002/fixproof/requests-2.31.0{DIGEST}"}


TAGGED = {"certbot/certbot:v2.6.0", "localhost:5001/fixproof/requests-2.30.0:it"}


def pods(documents: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(the object, its pod spec) for every Deployment and bare Pod."""
    return [
        (d, d["spec"]["template"]["spec"] if d["kind"] == "Deployment" else d["spec"])
        for d in documents
    ]


def test_six_success_test_workloads_two_live_ones_and_the_edge_cases() -> None:
    expected = Counter(verdict for _, verdict in demo_workloads.DEMO.values())
    assert expected == {"fixed": 2, "still_affected": 3, "unknown": 1}
    documents = demo_workloads.manifests(IMAGES, "auth-registry")
    by_namespace = Counter(d["metadata"]["namespace"] for d in documents)
    assert by_namespace == {"fixproof-demo": 6, "fixproof-live": 3, "fixproof-edge": 6}
    for _, spec in pods(documents):
        assert spec["automountServiceAccountToken"] is False
        assert spec["securityContext"]["runAsNonRoot"] is True
        for item in [*spec.get("initContainers", []), *spec["containers"]]:
            assert item["securityContext"]["allowPrivilegeEscalation"] is False
            if item["image"] == demo_workloads.SIDE_LOADED:
                assert item["imagePullPolicy"] == "Never"
            elif item["image"] in TAGGED:
                assert "@" not in item["image"]
            else:
                ImageRef.parse(item["image"])  # pinned by digest
        private = spec["containers"][0]["image"].startswith("localhost:5002/")
        assert spec.get("imagePullSecrets") == ([{"name": "auth-registry"}] if private else None)


def test_the_edge_namespace_covers_each_case_the_inventory_handles() -> None:
    documents = demo_workloads.manifests(IMAGES, "auth-registry")
    edge = {
        d["metadata"]["name"]: (d, spec)
        for d, spec in pods(documents)
        if d["metadata"]["namespace"] == "fixproof-edge"
    }
    assert edge["bare-pod"][0]["kind"] == "Pod"  # no owner
    two, spec = edge["two-replicas"]
    assert two["spec"]["replicas"] == 2
    assert [c["name"] for c in spec["initContainers"]] == ["setup", "proxy"]
    assert spec["initContainers"][1]["restartPolicy"] == "Always"  # a native sidecar
    assert [c["name"] for c in spec["containers"]] == ["app", "worker"]
    assert edge["pull-backoff"][1]["containers"][0]["image"].endswith("@sha256:" + "0" * 64)
    assert edge["unschedulable"][1]["nodeSelector"] == {"fixproof.example/no-such-node": "true"}
    # every (pod, container) the manifests create has an expected verdict, and no more
    created = {
        (name if d["kind"] == "Pod" else f"{name}-", c["name"])
        for name, (d, spec) in edge.items()
        for c in [*spec.get("initContainers", []), *spec["containers"]]
    }
    assert created == set(demo_workloads.EDGE)


def test_main_prints_the_manifests(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "images.json").write_text(json.dumps(IMAGES), encoding="utf-8")
    code = demo_workloads.main(
        ["--images", str(tmp_path / "images.json"), "--pull-secret", "auth-registry"]
    )
    assert code == 0
    documents = list(yaml.safe_load_all(capsys.readouterr().out))
    names = [d["metadata"]["name"] for d in documents]
    assert names[:9] == [*demo_workloads.DEMO, *demo_workloads.LIVE]
    assert len(names) == 15


def test_the_docker_runtime_workloads_use_short_names_as_users_write_them() -> None:
    documents = demo_workloads.docker_manifests()
    assert [d["metadata"]["name"] for d in documents] == list(demo_workloads.DOCKER)
    assert {d["metadata"]["namespace"] for d in documents} == {"fixproof-docker"}
    for document in documents:
        (item,) = document["spec"]["template"]["spec"]["containers"]
        image, _, reported = demo_workloads.DOCKER[document["metadata"]["name"]]
        assert item["image"] == image
        assert not image.startswith("docker.io/")  # short names, expanded by fixproof
        if reported is None:
            assert item["imagePullPolicy"] == "Never"
        else:
            assert ImageRef.parse(reported).registry == "docker.io"
    verdicts = Counter(verdict for _, verdict, _ in demo_workloads.DOCKER.values())
    assert verdicts == {"still_affected": 2, "fixed": 2, "unknown": 1}


def test_main_prints_the_docker_runtime_set_or_asks_for_its_inputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert demo_workloads.main(["--docker"]) == 0
    documents = list(yaml.safe_load_all(capsys.readouterr().out))
    assert len(documents) == len(demo_workloads.DOCKER)
    with pytest.raises(SystemExit):
        demo_workloads.main(["--images", "x.json"])
    assert "give --docker, or --images and --pull-secret" in capsys.readouterr().err
