"""A real Kubernetes client against an API server that never answers (ADR-0013 item 3).

A local TCP server accepts the connection and then says nothing. With the timeouts shortened,
fixproof's inventory must give up with an inventory error (exit 3, the reason), not hang. No
cluster is needed; it is marked `integration` because it opens a local socket.
"""

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from fixproof import inventory
from fixproof.inputs import Cluster

pytestmark = pytest.mark.integration


@pytest.fixture
def silent_server() -> Iterator[int]:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            held.append(connection)  # accepted, never answered

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join()
    for connection in held:
        connection.close()
    server.close()


def test_a_silent_api_server_ends_the_inventory_with_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, silent_server: int
) -> None:
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: silent\n"
        f"clusters:\n- name: silent\n  cluster:\n    server: http://127.0.0.1:{silent_server}\n"
        "users:\n- name: reader\n  user:\n    token: not-a-real-token\n"
        "contexts:\n- name: silent\n  context:\n    cluster: silent\n    user: reader\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KUBECONFIG", str(kubeconfig))
    monkeypatch.setattr(inventory, "API_TIMEOUT", (2, 2))
    started = time.monotonic()
    with pytest.raises(inventory.InventoryError, match=r"silent: list pods in demo: .*timed out"):
        inventory.inventory(Cluster(context="silent", namespaces=("demo",)))
    assert time.monotonic() - started < 60  # gave up; the default would wait for ever
