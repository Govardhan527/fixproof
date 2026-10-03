"""Kubernetes inventory (ADR-0010): the pods in scope, as workload assets.

fixproof reads with `list` on pods and `get` on replicasets only (deploy/kubernetes/). A
container's image is taken from its status `imageID`, which the kubelet fills with the runtime's
repository digest (SPEC_NOTES §12). A container without one is kept, with the reason, so it is
reported as `unknown` rather than dropped.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from fixproof.errors import FixproofError
from fixproof.inputs import Cluster
from fixproof.model import ImageRef, WorkloadAsset


class InventoryError(FixproofError):
    """A cluster could not be read (kubeconfig, permissions or connection)."""


@dataclass(frozen=True)
class ContainerInfo:
    name: str
    image_id: str
    waiting_reason: str | None = None


@dataclass(frozen=True)
class PodInfo:
    name: str
    containers: tuple[ContainerInfo, ...]  # init containers first, then the others
    controller: tuple[str, str] | None = None  # (kind, name) of the controlling owner


class PodSource(Protocol):
    """The part of the Kubernetes API fixproof uses."""

    def pods(self, namespace: str) -> list[PodInfo]: ...

    def replica_set_controller(self, namespace: str, name: str) -> tuple[str, str] | None: ...


@dataclass(frozen=True)
class Workload:
    asset: WorkloadAsset
    problem: str | None  # why the image could not be resolved, or None


def _controller(references: Iterable[Any] | None) -> tuple[str, str] | None:
    for reference in references or ():
        if reference.controller:
            return str(reference.kind), str(reference.name)
    return None


class KubernetesSource:
    """`PodSource` over the official client, for one kubeconfig context."""

    def __init__(self, context: str) -> None:
        # Imported here so image-only runs never load the Kubernetes client.
        from kubernetes import client, config

        try:
            api = config.new_client_from_config(context=context)
        except (config.ConfigException, OSError, TypeError) as exc:
            raise InventoryError(f"cannot load kubeconfig context {context!r}: {exc}") from exc
        self._context = context
        self._core = client.CoreV1Api(api)
        self._apps = client.AppsV1Api(api)

    def _call(self, what: str, call: Callable[[], Any]) -> Any:
        from kubernetes.client.exceptions import ApiException
        from urllib3.exceptions import HTTPError

        try:
            return call()
        except ApiException as exc:
            raise InventoryError(f"{self._context}: {what}: {exc.status} {exc.reason}") from exc
        except (HTTPError, OSError) as exc:
            raise InventoryError(f"{self._context}: {what}: {exc}") from exc

    def pods(self, namespace: str) -> list[PodInfo]:
        listing = self._call(
            f"list pods in {namespace}", lambda: self._core.list_namespaced_pod(namespace)
        )
        pods = []
        for pod in listing.items:
            status, spec = pod.status, pod.spec
            statuses = {
                item.name: item
                for item in [
                    *(status.init_container_statuses or []),
                    *(status.container_statuses or []),
                ]
            }
            containers = []
            # The spec names every container, so one with no status yet (an unscheduled pod) is
            # still reported, as not started.
            for name in [c.name for c in [*(spec.init_containers or []), *spec.containers]]:
                item = statuses.get(name)
                if item is None:
                    waiting_reason = f"no status yet, pod {status.phase or 'Pending'}"
                    containers.append(ContainerInfo(name, "", waiting_reason))
                    continue
                waiting = item.state.waiting if item.state else None
                containers.append(
                    ContainerInfo(
                        name=name,
                        image_id=item.image_id or "",
                        waiting_reason=waiting.reason if waiting else None,
                    )
                )
            pods.append(
                PodInfo(
                    name=pod.metadata.name,
                    containers=tuple(containers),
                    controller=_controller(pod.metadata.owner_references),
                )
            )
        return pods

    def replica_set_controller(self, namespace: str, name: str) -> tuple[str, str] | None:
        replica_set = self._call(
            f"get replicaset {name} in {namespace}",
            lambda: self._apps.read_namespaced_replica_set(name, namespace),
        )
        return _controller(replica_set.metadata.owner_references)


def image_from_id(image_id: str, waiting_reason: str | None) -> tuple[ImageRef | None, str | None]:
    """The image a container runs, or None and the reason it cannot be resolved."""
    if not image_id:
        state = f" ({waiting_reason})" if waiting_reason else ""
        return None, f"image digest not resolved: the container has not started{state}"
    try:
        return ImageRef.parse(image_id), None
    except ValueError:
        return None, f"image digest not resolved: imageID {image_id!r} has no registry digest"


def inventory(
    cluster: Cluster, source_factory: Callable[[str], PodSource] = KubernetesSource
) -> list[Workload]:
    """Every container of every pod in the cluster's namespaces, sorted by namespace and pod."""
    source = source_factory(cluster.context)
    owners: dict[tuple[str, str], str | None] = {}
    workloads = []
    for namespace in cluster.namespaces:
        for pod in sorted(source.pods(namespace), key=lambda p: p.name):
            owner = None
            if pod.controller is not None:
                kind, name = pod.controller
                if kind == "ReplicaSet":
                    if (namespace, name) not in owners:
                        top = source.replica_set_controller(namespace, name)
                        owners[(namespace, name)] = f"{top[0]}/{top[1]}" if top else None
                    owner = owners[(namespace, name)] or f"{kind}/{name}"
                else:
                    owner = f"{kind}/{name}"
            for container in pod.containers:
                image, problem = image_from_id(container.image_id, container.waiting_reason)
                asset = WorkloadAsset(
                    cluster=cluster.context,
                    namespace=namespace,
                    pod=pod.name,
                    container=container.name,
                    image=image,
                    owner=owner,
                )
                workloads.append(Workload(asset, problem))
    return workloads
