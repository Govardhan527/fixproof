"""M4 integration: fixproof against the kind demo cluster (ADR-0010, SUCCESS TEST step 1).

Needs FIXPROOF_IT_IMAGES and FIXPROOF_IT_KUBECONFIG, both written by `scripts/demo_cluster.sh up`
in the CI `integration` job; kubectl is taken from the same work directory. fixproof runs with
the read-only `fixproof-reader` token, set up exactly as deploy/kubernetes/ and the README say
(ADR-0010 item 7 and Amendment 1), and no registry credentials. Locally these tests skip
without the variables; in CI they fail instead.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

import demo_workloads
from fixproof.validation import build_validator, check_openvex, load_schema, schema_errors

pytestmark = pytest.mark.integration

CVE = "CVE-2023-32681"
CONTEXT = "kind-fixproof"
OPEN, AUTH = "localhost:5001", "localhost:5002"
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
    tmp_path: Path,
    kubeconfig: str,
    namespaces: list[str],
    registries: list[str],
    *flags: str,
    images: tuple[str, ...] = (),
    docker_config: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    scope = f'schema_version: "1.0.0"\nregistries: [{", ".join(registries)}]\n'
    if images:
        scope += "images:\n" + "".join(f"  - {image}\n" for image in images)
    scope += f"clusters:\n  - context: {CONTEXT}\n    namespaces: [{', '.join(namespaces)}]\n"
    (tmp_path / "fix.yaml").write_text(FIX, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(scope, encoding="utf-8")
    if docker_config is None:  # no registry credentials at all
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
        env={**os.environ, "DOCKER_CONFIG": str(docker_config), "KUBECONFIG": kubeconfig},
        check=False,
        timeout=3600,
    )  # fmt: skip


def report_of(done: subprocess.CompletedProcess[str]) -> dict[str, Any]:
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
    return bundle


def test_success_test_six_workloads(tmp_path: Path, setup: tuple[dict[str, str], str]) -> None:
    images, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, ["fixproof-demo"], [OPEN, AUTH], "--json")
    report = report_of(done)
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
    assert "UNAUTHORIZED" in unknown
    assert done.returncode == 1
    check_bundle(tmp_path / "out")
    vex = json.loads((tmp_path / "out" / "openvex.json").read_text())
    assert sorted(s["status"] for s in vex["statements"]) == [
        "affected", "affected", "affected", "fixed", "fixed", "under_investigation",
    ]  # fmt: skip


def test_human_output_names_every_pod_digest_and_reason(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    images, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, ["fixproof-demo"], [OPEN, AUTH])
    assert done.returncode == 1, done.stderr
    for name, (fixture, verdict) in demo_workloads.DEMO.items():
        line = re.search(
            rf"^{verdict} +{CONTEXT}/fixproof-demo/{name}-\S+/app  Deployment/{name}\n"
            rf" {{16}}{re.escape(images[fixture])}\n {{16}}\S",
            done.stdout,
            re.MULTILINE,
        )
        assert line, (name, done.stdout)
    assert "2 fixed, 3 still_affected, 1 unknown; evidence in" in done.stdout


def test_real_certbot_workloads(tmp_path: Path, setup: tuple[dict[str, str], str]) -> None:
    _, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, ["fixproof-live"], ["docker.io"], "--json")
    found = by_owner(report_of(done))
    for name, (image, verdict) in demo_workloads.LIVE.items():
        assert found[name]["verdict"] == verdict, (name, found[name]["reason"])
        if "@" in image:
            assert found[name]["asset"] == image
    # by short name and tag in the pod spec; the node reports the full name and the digest
    assert found["certbot-by-tag"]["asset"] == demo_workloads.LIVE["certbot-2-6-0"][0]
    assert done.returncode == 1


def test_two_namespaces_in_one_run_with_one_token(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    """One account, bound by the same Role file in each namespace (ADR-0010 Amendment 1)."""
    _, kubeconfig = setup
    namespaces = ["fixproof-demo", "fixproof-live"]
    done = verify(tmp_path, kubeconfig, namespaces, [OPEN, AUTH, "docker.io"], "--json")
    report = report_of(done)
    assert report["summary"] == {"fixed": 3, "still_affected": 5, "unknown": 1}
    seen = [item["workload"].split("/")[1] for item in report["assets"]]
    assert seen == ["fixproof-demo"] * 6 + ["fixproof-live"] * 3  # in scope order
    assert done.returncode == 1


def test_a_registry_outside_the_allowlist_is_never_read(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    """Only the password-protected registry is allowed: the five open-registry pods are unknown
    without being read, and the one allowed pod is unknown because fixproof has no password."""
    _, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, ["fixproof-demo"], [AUTH], "--json")
    report = report_of(done)
    assert report["summary"] == {"fixed": 0, "still_affected": 0, "unknown": 6}
    found = by_owner(report)
    for name in demo_workloads.DEMO:
        if name == "partner-gateway":
            assert found[name]["reason"].startswith("both methods failed")
        else:
            assert found[name]["reason"] == (
                f"registry not in scope: {OPEN}; fixproof did not read the image"
            )
    assert done.returncode == 2
    bundle = check_bundle(tmp_path / "out")
    for record in bundle["assets"]:
        if record["asset"]["image"]["registry"] == OPEN:
            assert record["results"] == []  # no method ran
    assert not any((tmp_path / "out" / "raw").iterdir())  # nothing was read successfully


def test_with_registry_credentials_the_private_workload_gets_a_real_verdict(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    """A user who gives fixproof read access to a private registry, through the standard Docker
    config, gets a real verdict for it, and the credential appears nowhere in what fixproof
    prints or writes (ADR-0007: credentials are never logged or stored)."""
    images, kubeconfig = setup
    credentials = Path(kubeconfig).parent / "docker"  # demo_cluster.sh's `docker login`
    auth = json.loads((credentials / "config.json").read_text())["auths"][AUTH]["auth"]
    password = base64.b64decode(auth).decode().split(":", 1)[1]
    done = verify(
        tmp_path, kubeconfig, ["fixproof-demo"], [OPEN, AUTH], "--json", docker_config=credentials
    )
    report = report_of(done)
    assert report["summary"] == {"fixed": 3, "still_affected": 3, "unknown": 0}
    private = by_owner(report)["partner-gateway"]
    assert private["verdict"] == "fixed", private["reason"]
    assert private["asset"] == images["auth/requests-2.31.0"]
    assert done.returncode == 1
    check_bundle(tmp_path / "out")
    written = [p.read_text() for p in (tmp_path / "out").rglob("*") if p.is_file()]
    for text in [done.stdout, done.stderr, *written]:
        assert password not in text
        assert auth not in text


def edge_key(workload: str) -> tuple[str, str]:
    """`cluster/namespace/pod/container` -> the demo_workloads.EDGE key for it."""
    _, _, pod, container = workload.split("/")
    prefixes = [p for p, c in demo_workloads.EDGE if c == container and pod.startswith(p)]
    assert len(prefixes) == 1, workload
    return prefixes[0], container


def test_edge_cases_on_a_real_node(tmp_path: Path, setup: tuple[dict[str, str], str]) -> None:
    """Init containers, sidecars, two replicas, a bare pod, an ephemeral container (skipped),
    a pull failure, an unscheduled pod and a side-loaded image; an image listed in `images`
    that workloads also run is scanned once (ADR-0010 items 1 to 5)."""
    images, kubeconfig = setup
    shared = images["requests-2.30.0"]
    done = verify(tmp_path, kubeconfig, ["fixproof-edge"], [OPEN], "--json", images=(shared,))
    report = report_of(done)
    image_line, workloads = report["assets"][0], report["assets"][1:]
    assert (image_line["asset"], image_line["workload"]) == (shared, None)
    assert image_line["verdict"] == "still_affected"
    keys = Counter(edge_key(item["workload"]) for item in workloads)
    assert keys == {key: 2 if key[0] == "two-replicas-" else 1 for key in demo_workloads.EDGE}
    assert all(item["workload"].rsplit("/", 1)[1] != "debugger" for item in workloads)
    for item in workloads:
        verdict, text = demo_workloads.EDGE[edge_key(item["workload"])]
        assert item["verdict"] == verdict, (item["workload"], item["reason"])
        assert text in item["reason"], (item["workload"], item["reason"])
        pod = item["workload"].split("/")[2]
        if pod == "bare-pod":
            assert item["owner"] is None
        else:
            assert item["owner"] == f"Deployment/{pod.rsplit('-', 2)[0]}"
    assert done.returncode == 1

    bundle = check_bundle(tmp_path / "out")
    by_digest: dict[str, set[tuple[str | None, ...]]] = {}
    for record in bundle["assets"]:
        image = record["asset"]["image"]
        refs = tuple(result["raw_ref"] for result in record["results"])
        if image is not None and record["results"]:
            by_digest.setdefault(image["digest"], set()).add(refs)
    assert all(len(refs) == 1 for refs in by_digest.values())  # replicas share evidence
    scanned = {images[n] for n in ("requests-2.30.0", "requests-2.32.3", "no-requests")}
    scanned.add(images["requests-2.25.1"])
    assert len(by_digest) == len(scanned)
    raw = sorted(p.name for p in (tmp_path / "out" / "raw").iterdir())
    assert len(raw) == 2 * len(scanned)  # each image's two outputs written once


def test_a_side_loaded_image_is_unknown_even_when_docker_hub_is_allowed(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    """The node names a `kind load` image docker.io/library/import-<date>; with docker.io in the
    allowlist fixproof tries that name, finds nothing, and says unknown, never fixed."""
    _, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, ["fixproof-edge"], [OPEN, "docker.io"], "--json")
    items = [
        item
        for item in report_of(done)["assets"]
        if item["workload"].split("/")[2].startswith("side-loaded-")
    ]
    assert len(items) == 1
    (item,) = items
    assert re.fullmatch(r"docker\.io/library/import-[0-9-]+@sha256:[0-9a-f]{64}", item["asset"])
    assert item["verdict"] == "unknown"
    assert item["reason"].startswith("both methods failed"), item["reason"]


def kubectl_can_i(kubeconfig: str, *args: str) -> bool:
    kubectl = Path(kubeconfig).parent / "bin" / "kubectl"  # demo_cluster.sh's layout
    done = subprocess.run(
        [str(kubectl), "--kubeconfig", kubeconfig, "auth", "can-i", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert done.stdout.strip() in {"yes", "no"}, done.stderr
    return done.stdout.strip() == "yes"


ALLOWED = [
    (verb, resource, namespace)
    for namespace in ("fixproof-demo", "fixproof-live", "fixproof-edge")
    for resource in ("pods", "replicasets.apps")
    for verb in ("get", "list")
]
DENIED = [
    ("watch", "pods", "fixproof-demo"),
    ("create", "pods", "fixproof-demo"),
    ("delete", "pods", "fixproof-demo"),
    ("get", "secrets", "fixproof-demo"),  # the image pull secret is there
    ("list", "secrets", "fixproof-demo"),
    ("get", "deployments.apps", "fixproof-demo"),
    ("list", "pods", "kube-system"),
    ("list", "pods", "default"),
    ("get", "replicasets.apps", "kube-system"),
    ("create", "serviceaccounts", "fixproof"),
]


@pytest.mark.parametrize(("verb", "resource", "namespace"), ALLOWED)
def test_the_reader_may_get_and_list_pods_and_replicasets(
    setup: tuple[dict[str, str], str], verb: str, resource: str, namespace: str
) -> None:
    assert kubectl_can_i(setup[1], verb, resource, "-n", namespace)


@pytest.mark.parametrize(("verb", "resource", "namespace"), DENIED)
def test_the_reader_may_do_nothing_else(
    setup: tuple[dict[str, str], str], verb: str, resource: str, namespace: str
) -> None:
    assert not kubectl_can_i(setup[1], verb, resource, "-n", namespace)


def test_the_reader_has_no_cluster_wide_or_subresource_access(
    setup: tuple[dict[str, str], str],
) -> None:
    kubeconfig = setup[1]
    assert not kubectl_can_i(kubeconfig, "list", "nodes")
    assert not kubectl_can_i(kubeconfig, "list", "pods", "--all-namespaces")
    assert not kubectl_can_i(kubeconfig, "*", "*", "-n", "fixproof-demo")
    for verb, subresource, namespace in [
        ("create", "exec", "fixproof-demo"),
        ("get", "log", "fixproof-demo"),
        ("patch", "ephemeralcontainers", "fixproof-edge"),
    ]:
        assert not kubectl_can_i(
            kubeconfig, verb, "pods", f"--subresource={subresource}", "-n", namespace
        )
    assert not kubectl_can_i(
        kubeconfig, "create", "serviceaccounts", "--subresource=token", "-n", "fixproof"
    )


def test_the_reader_cannot_list_other_namespaces(
    tmp_path: Path, setup: tuple[dict[str, str], str]
) -> None:
    _, kubeconfig = setup
    done = verify(tmp_path, kubeconfig, ["kube-system"], [OPEN])
    assert done.returncode == 3
    assert f"{CONTEXT}: list pods in kube-system: 403 Forbidden" in done.stderr
