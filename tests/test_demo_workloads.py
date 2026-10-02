"""The demo cluster's workloads match the SUCCESS TEST: 2 fixed, 3 still_affected, 1 unknown."""

import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

import demo_workloads
from fixproof.model import ImageRef

DIGEST = "@sha256:" + "ab" * 32
IMAGES = {
    name: f"localhost:5001/fixproof/{name}{DIGEST}"
    for name in ("requests-2.30.0", "requests-2.25.1", "venv-only", "requests-2.31.0")
} | {
    "requests-2.32.3": f"localhost:5001/fixproof/requests-2.32.3{DIGEST}",
    "auth/requests-2.31.0": f"localhost:5002/fixproof/requests-2.31.0{DIGEST}",
}


def test_six_success_test_workloads_and_two_live_ones() -> None:
    expected = Counter(verdict for _, verdict in demo_workloads.DEMO.values())
    assert expected == {"fixed": 2, "still_affected": 3, "unknown": 1}
    documents = demo_workloads.manifests(IMAGES, "auth-registry")
    by_namespace = Counter(d["metadata"]["namespace"] for d in documents)
    assert by_namespace == {"fixproof-demo": 6, "fixproof-live": 2}
    for document in documents:
        pod = document["spec"]["template"]["spec"]
        (container,) = pod["containers"]
        ImageRef.parse(container["image"])  # every image is pinned by digest
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert pod["automountServiceAccountToken"] is False
        secret = pod.get("imagePullSecrets")
        private = container["image"].startswith("localhost:5002/")
        assert secret == ([{"name": "auth-registry"}] if private else None)


def test_main_prints_the_manifests(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "images.json").write_text(json.dumps(IMAGES), encoding="utf-8")
    code = demo_workloads.main(
        ["--images", str(tmp_path / "images.json"), "--pull-secret", "auth-registry"]
    )
    assert code == 0
    documents = list(yaml.safe_load_all(capsys.readouterr().out))
    assert [d["metadata"]["name"] for d in documents] == [
        *demo_workloads.DEMO,
        *demo_workloads.LIVE,
    ]
