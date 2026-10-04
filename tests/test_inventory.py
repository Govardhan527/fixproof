"""Kubernetes inventory (ADR-0010) against a fake cluster and the real client's models."""

from pathlib import Path
from typing import Any

import pytest
from kubernetes import client as k8s
from kubernetes import config as k8s_config
from kubernetes.client.exceptions import ApiException

from fixproof.inputs import Cluster
from fixproof.inventory import (
    API_TIMEOUT,
    ContainerInfo,
    InventoryError,
    KubernetesSource,
    PodInfo,
    image_from_id,
    inventory,
)

DIGEST = "sha256:" + "ab" * 32
IMAGE_ID = f"localhost:5001/fixproof/requests-2.31.0@{DIGEST}"
CLUSTER = Cluster(context="kind-fixproof", namespaces=("demo", "other"))


class FakeSource:
    def __init__(self, pods: dict[str, list[PodInfo]], replica_sets: dict[str, Any]) -> None:
        self._pods, self._replica_sets, self.reads = pods, replica_sets, 0

    def pods(self, namespace: str) -> list[PodInfo]:
        return self._pods.get(namespace, [])

    def replica_set_controller(self, namespace: str, name: str) -> tuple[str, str] | None:
        self.reads += 1
        controller: tuple[str, str] | None = self._replica_sets.get(name)
        return controller


def test_containers_become_workloads_with_their_owner() -> None:
    source = FakeSource(
        {
            "demo": [
                PodInfo("web-7d9-b", (ContainerInfo("app", IMAGE_ID),), ("ReplicaSet", "web-7d9")),
                PodInfo("web-7d9-a", (ContainerInfo("app", IMAGE_ID),), ("ReplicaSet", "web-7d9")),
                PodInfo(
                    "job-x",
                    (ContainerInfo("init", IMAGE_ID), ContainerInfo("run", IMAGE_ID)),
                    ("Job", "job"),
                ),
                PodInfo("bare", (ContainerInfo("app", IMAGE_ID),)),
            ]
        },
        {"web-7d9": ("Deployment", "web")},
    )
    workloads = inventory(CLUSTER, lambda context: source)
    assert [(w.asset.pod, w.asset.container, w.asset.owner) for w in workloads] == [
        ("bare", "app", None),
        ("job-x", "init", "Job/job"),
        ("job-x", "run", "Job/job"),
        ("web-7d9-a", "app", "Deployment/web"),
        ("web-7d9-b", "app", "Deployment/web"),
    ]
    assert source.reads == 1  # each ReplicaSet is read once
    first = workloads[0].asset
    assert (first.cluster, first.namespace, first.location) == (
        "kind-fixproof",
        "demo",
        "kind-fixproof/demo/bare/app",
    )
    assert first.image is not None
    assert first.image.reference == IMAGE_ID
    assert all(w.problem is None for w in workloads)


def test_an_orphan_replica_set_names_itself() -> None:
    source = FakeSource(
        {"demo": [PodInfo("rs-a", (ContainerInfo("app", IMAGE_ID),), ("ReplicaSet", "rs"))]}, {}
    )
    assert inventory(CLUSTER, lambda context: source)[0].asset.owner == "ReplicaSet/rs"


@pytest.mark.parametrize(
    ("image_id", "waiting", "problem"),
    [
        ("", "ImagePullBackOff", "the container has not started (ImagePullBackOff)"),
        ("", None, "the container has not started"),
        ("sha256:" + "cd" * 32, None, "has no registry digest"),
        ("docker://sha256:" + "cd" * 32, None, "has no registry digest"),  # cri-dockerd, no digest
        ("docker-pullable://nginx", None, "has no registry digest"),  # no digest at all
    ],
)
def test_unresolved_images_keep_the_reason(
    image_id: str, waiting: str | None, problem: str
) -> None:
    image, reason = image_from_id(image_id, waiting)
    assert image is None
    assert reason is not None
    assert problem in reason


@pytest.mark.parametrize(
    ("image_id", "reference"),
    [
        # containerd: already in full
        (IMAGE_ID, IMAGE_ID),
        (f"docker.io/library/nginx@{DIGEST}", f"docker.io/library/nginx@{DIGEST}"),
        # cri-dockerd: docker-pullable:// and Docker's familiar names (SPEC_NOTES §12, §15)
        (f"docker-pullable://nginx@{DIGEST}", f"docker.io/library/nginx@{DIGEST}"),
        (f"docker-pullable://certbot/certbot@{DIGEST}", f"docker.io/certbot/certbot@{DIGEST}"),
        (f"docker-pullable://docker.io/nginx@{DIGEST}", f"docker.io/library/nginx@{DIGEST}"),
        (
            f"docker-pullable://index.docker.io/library/nginx@{DIGEST}",
            f"docker.io/library/nginx@{DIGEST}",
        ),
        (f"docker-pullable://index.docker.io/nginx@{DIGEST}", f"docker.io/library/nginx@{DIGEST}"),
        (f"docker-pullable://Registry/app@{DIGEST}", f"Registry/app@{DIGEST}"),  # not lower case
        (f"docker-pullable://localhost/app@{DIGEST}", f"localhost/app@{DIGEST}"),
        (
            f"docker-pullable://localhost:5000/team/app@{DIGEST}",
            f"localhost:5000/team/app@{DIGEST}",
        ),
        (
            f"docker-pullable://registry.example.com/team/app@{DIGEST}",
            f"registry.example.com/team/app@{DIGEST}",
        ),
    ],
)
def test_image_ids_from_containerd_and_cri_dockerd(image_id: str, reference: str) -> None:
    image, problem = image_from_id(image_id, None)
    assert problem is None
    assert image is not None
    assert image.reference == reference


def k8s_pod(
    name: str, statuses: list[Any], init: list[Any] | None = None, owner: Any = None
) -> Any:
    def spec(items: list[Any] | None) -> list[Any] | None:
        return [k8s.V1Container(name=item.name) for item in items] if items else None

    return k8s.V1Pod(
        metadata=k8s.V1ObjectMeta(name=name, owner_references=[owner] if owner else None),
        spec=k8s.V1PodSpec(containers=spec(statuses), init_containers=spec(init)),
        status=k8s.V1PodStatus(container_statuses=statuses, init_container_statuses=init),
    )


def status(name: str, image_id: str, waiting: str | None = None) -> Any:
    state = (
        k8s.V1ContainerState(waiting=k8s.V1ContainerStateWaiting(reason=waiting))
        if waiting
        else None
    )
    return k8s.V1ContainerStatus(
        name=name, image="x", image_id=image_id, ready=False, restart_count=0, state=state
    )


def owner(kind: str, name: str, controller: bool = True) -> Any:
    return k8s.V1OwnerReference(
        api_version="apps/v1", kind=kind, name=name, uid="u", controller=controller
    )


class FakeCore:
    def __init__(self, pods: list[Any], error: Exception | None = None) -> None:
        self._pods, self._error = pods, error

    def list_namespaced_pod(self, namespace: str, _request_timeout: Any = None) -> Any:
        assert _request_timeout == API_TIMEOUT  # every call has a timeout (ADR-0013)
        if self._error:
            raise self._error
        return k8s.V1PodList(items=self._pods)


class FakeApps:
    def read_namespaced_replica_set(
        self, name: str, namespace: str, _request_timeout: Any = None
    ) -> Any:
        assert _request_timeout == API_TIMEOUT
        return k8s.V1ReplicaSet(
            metadata=k8s.V1ObjectMeta(name=name, owner_references=[owner("Deployment", "web")])
        )


def patch_client(
    monkeypatch: pytest.MonkeyPatch, core: FakeCore, loads: list[dict[str, Any]] | None = None
) -> None:
    def load(**kwargs: Any) -> object:
        if loads is not None:
            loads.append(kwargs)
        return object()

    monkeypatch.setattr(k8s_config, "new_client_from_config", load)
    monkeypatch.setattr(k8s, "CoreV1Api", lambda api: core)
    monkeypatch.setattr(k8s, "AppsV1Api", lambda api: FakeApps())


def test_kubernetes_source_reads_statuses_and_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    pods = [
        k8s_pod(
            "web-1",
            [status("app", IMAGE_ID), status("sidecar", "", waiting="ErrImagePull")],
            init=[status("setup", IMAGE_ID)],
            owner=owner("ReplicaSet", "web-7d9"),
        ),
        k8s_pod("bare", [status("app", IMAGE_ID)], owner=owner("Node", "n", controller=False)),
        k8s.V1Pod(  # not scheduled yet: the spec names the container, the status has none
            metadata=k8s.V1ObjectMeta(name="pending"),
            spec=k8s.V1PodSpec(containers=[k8s.V1Container(name="app")]),
            status=k8s.V1PodStatus(phase="Pending"),
        ),
    ]
    patch_client(monkeypatch, FakeCore(pods))
    workloads = inventory(Cluster(context="ctx", namespaces=("demo",)))
    assert [
        (w.asset.pod, w.asset.container, w.asset.owner, w.problem is None) for w in workloads
    ] == [
        ("bare", "app", None, True),
        ("pending", "app", None, False),
        ("web-1", "setup", "Deployment/web", True),
        ("web-1", "app", "Deployment/web", True),
        ("web-1", "sidecar", "Deployment/web", False),
    ]
    assert workloads[-1].problem == (
        "image digest not resolved: the container has not started (ErrImagePull)"
    )
    assert workloads[1].problem == (
        "image digest not resolved: the container has not started (no status yet, pod Pending)"
    )


def test_kubernetes_api_errors_are_inventory_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_client(monkeypatch, FakeCore([], ApiException(status=403, reason="Forbidden")))
    with pytest.raises(InventoryError, match="ctx: list pods in demo: 403 Forbidden"):
        inventory(Cluster(context="ctx", namespaces=("demo",)))
    patch_client(monkeypatch, FakeCore([], ConnectionRefusedError("refused")))
    with pytest.raises(InventoryError, match="ctx: list pods in demo: refused"):
        inventory(Cluster(context="ctx", namespaces=("demo",)))


def test_kubeconfig_is_read_from_the_environment_and_never_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loads: list[dict[str, Any]] = []
    patch_client(monkeypatch, FakeCore([]), loads)
    monkeypatch.setenv("KUBECONFIG", "/etc/fixproof/reader.kubeconfig")
    KubernetesSource("ctx")
    monkeypatch.delenv("KUBECONFIG")
    KubernetesSource("ctx")
    assert loads == [
        {
            "config_file": "/etc/fixproof/reader.kubeconfig",
            "context": "ctx",
            "persist_config": False,
        },
        {"config_file": "~/.kube/config", "context": "ctx", "persist_config": False},
    ]


def test_a_missing_context_is_an_inventory_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(context: str, **kwargs: Any) -> Any:
        raise k8s_config.ConfigException(f"Expected key {context} in contexts")

    monkeypatch.setattr(k8s_config, "new_client_from_config", missing)
    with pytest.raises(InventoryError, match="cannot load kubeconfig context 'nope'"):
        KubernetesSource("nope")


def test_a_silent_api_server_is_an_inventory_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A read timeout from the client becomes exit 3 with the reason (ADR-0013 item 3)."""
    from urllib3.exceptions import ReadTimeoutError

    timeout = ReadTimeoutError(
        None, "/api/v1/namespaces/demo/pods", "Read timed out. (read timeout=60)"
    )
    patch_client(monkeypatch, FakeCore([], timeout))
    with pytest.raises(InventoryError, match=r"ctx: list pods in demo: .*Read timed out"):
        inventory(Cluster(context="ctx", namespaces=("demo",)))


def test_an_api_server_that_never_accepts_is_an_inventory_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib3.exceptions import ConnectTimeoutError

    patch_client(monkeypatch, FakeCore([], ConnectTimeoutError("connect timeout=10")))
    with pytest.raises(InventoryError, match="ctx: list pods in demo: connect timeout=10"):
        inventory(Cluster(context="ctx", namespaces=("demo",)))


PLUGIN = """\
import json, os, sys
info = json.loads(os.environ["KUBERNETES_EXEC_INFO"])  # what a real plugin is given
mode = sys.argv[1]
if mode == "expired":
    print("error: the SSO session has expired; sign in again", file=sys.stderr)
    sys.exit(1)
version = "client.authentication.k8s.io/v1alpha1" if mode == "wrong-version" else info["apiVersion"]
status = {"token": open(sys.argv[2]).read().strip()} if mode == "token" else {}
print(json.dumps({"apiVersion": version, "kind": "ExecCredential", "status": status}))
"""


def exec_kubeconfig(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, api: str = "v1beta1"
) -> None:
    """A kubeconfig whose user signs in through an exec plugin, as managed clusters' do."""
    import sys

    import yaml

    plugin = tmp_path / "plugin.py"
    plugin.write_text(PLUGIN, encoding="utf-8")
    secret = tmp_path / "token"  # the plugin's own credential store, not the kubeconfig
    secret.write_text("secret-token-from-the-plugin", encoding="utf-8")
    user = {
        "exec": {
            "apiVersion": f"client.authentication.k8s.io/{api}",
            "command": sys.executable,
            "args": [str(plugin), mode, str(secret)],
            "interactiveMode": "Never",
        }
    }
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "c", "cluster": {"server": "https://127.0.0.1:1"}}],
        "users": [{"name": "u", "user": user}],
        "contexts": [{"name": "managed", "context": {"cluster": "c", "user": "u"}}],
        "current-context": "managed",
    }
    path = tmp_path / "kubeconfig"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setenv("KUBECONFIG", str(path))


@pytest.mark.parametrize("api", ["v1beta1", "v1"])
def test_an_exec_plugin_signs_in_without_a_token_in_the_kubeconfig(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, api: str
) -> None:
    exec_kubeconfig(tmp_path, monkeypatch, "token", api)
    source = KubernetesSource("managed")  # loads the config and runs the plugin; no API call
    configuration = source._core.api_client.configuration
    sent = configuration.auth_settings()["BearerToken"]  # the header every API call carries
    assert (sent["key"], sent["value"]) == ("authorization", "Bearer secret-token-from-the-plugin")
    assert configuration.refresh_api_key_hook is not None  # it runs the plugin again on expiry
    assert "secret-token" not in (tmp_path / "kubeconfig").read_text()  # nothing written back


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        ("expired", "exec: process returned 1. error: the SSO session has expired; sign in again"),
        ("wrong-version", "exec: plugin api version client.authentication.k8s.io/v1alpha1"),
        ("no-token", "exec: missing token or clientCertificateData field in plugin output"),
    ],
)  # fmt: skip
def test_a_failing_exec_plugin_stops_the_run_with_its_own_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    reason: str,
) -> None:
    exec_kubeconfig(tmp_path, monkeypatch, mode)
    with pytest.raises(InventoryError) as caught:
        KubernetesSource("managed")
    message = str(caught.value)
    assert message.startswith(
        "cannot sign in to kubeconfig context 'managed': its exec plugin failed: "
    )
    assert reason in message
    assert capsys.readouterr().err == ""  # said once, by fixproof, not also by the client's log
