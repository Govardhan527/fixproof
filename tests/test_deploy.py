"""The Kubernetes access fixproof asks for (ADR-0010 item 7) is read-only and minimal."""

import ast
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "kubernetes"
GRANTED = [
    {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
    {"apiGroups": ["apps"], "resources": ["replicasets"], "verbs": ["get", "list"]},
]
# Each Kubernetes client call fixproof makes, as the (API group, resource, verb) it needs.
CALLS = {
    "list_namespaced_pod": ("", "pods", "list"),
    "read_namespaced_replica_set": ("apps", "replicasets", "get"),
}


def documents(name: str) -> list[dict[str, Any]]:
    return list(yaml.safe_load_all((DEPLOY / name).read_text(encoding="utf-8")))


def test_the_account_is_a_service_account_with_no_mounted_token() -> None:
    namespace, account = documents("fixproof-reader.yaml")
    assert (namespace["kind"], namespace["metadata"]["name"]) == ("Namespace", "fixproof")
    assert account["kind"] == "ServiceAccount"
    assert account["metadata"] == {"name": "fixproof-reader", "namespace": "fixproof"}
    assert account["automountServiceAccountToken"] is False


def test_the_role_grants_get_and_list_on_pods_and_replicasets_only() -> None:
    role, binding = documents("fixproof-reader-role.yaml")
    assert role["kind"] == "Role"  # namespaced: never a ClusterRole
    assert role["rules"] == GRANTED
    assert "namespace" not in role["metadata"]  # applied to each namespace in scope
    assert binding["kind"] == "RoleBinding"
    assert "namespace" not in binding["metadata"]
    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": "fixproof-reader",
    }
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "fixproof-reader", "namespace": "fixproof"}
    ]


def test_every_api_call_in_the_inventory_is_granted() -> None:
    tree = ast.parse((ROOT / "src" / "fixproof" / "inventory.py").read_text(encoding="utf-8"))
    called = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr in {"_core", "_apps"}
    }
    assert called == set(CALLS)
    granted = {
        (group, resource, verb)
        for rule in GRANTED
        for group in rule["apiGroups"]
        for resource in rule["resources"]
        for verb in rule["verbs"]
    }
    assert set(CALLS.values()) <= granted
