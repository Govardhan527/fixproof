"""Signing in the way managed clusters and cloud registries do, proven on the kind demo cluster
(ADR-0015): no cloud account, the same mechanisms.

- A kubeconfig whose user is an exec plugin (EKS, GKE and AKS kubeconfigs work this way): the
  plugin hands the client the reader account's token, which the kubeconfig never holds; it
  works with `client.authentication.k8s.io/v1beta1` and `v1`, and a failing plugin stops the run
  with exit 3 and the plugin's own message.
- A Docker credential helper (cloud registries' sign-in works this way), named in `credHelpers`
  or as the `credsStore`: crane, Syft and Grype all ask it for the password-protected registry,
  so the private workload gets a real verdict.

No secret appears in what fixproof prints or writes.
"""

import base64
import json
import os
import stat
import sys
from pathlib import Path

import pytest
import yaml
from cluster_helpers import assert_nowhere, by_owner, check_bundle, report_of, run_verify

pytestmark = pytest.mark.integration

CONTEXT = "kind-fixproof"
OPEN, AUTH = "localhost:5001", "localhost:5002"
PLUGIN = """\
import json, os, sys
info = json.loads(os.environ["KUBERNETES_EXEC_INFO"])
if sys.argv[1] == "expired":
    print("error: the SSO session has expired; sign in again", file=sys.stderr)
    sys.exit(1)
token = open(sys.argv[2], encoding="utf-8").read().strip()
print(json.dumps({"apiVersion": info["apiVersion"], "kind": "ExecCredential",
                  "status": {"token": token, "expirationTimestamp": "2099-01-01T00:00:00Z"}}))
"""
# The Docker credential helper protocol (SPEC_NOTES §21): `get` reads a server URL on stdin.
HELPER = """\
#!/bin/sh
server="$(cat)"
echo "$1 $server" >> "$FIXPROOF_HELPER_LOG"
if [ "$1" = get ] && [ "$server" = "{registry}" ]; then
  cat "{answer}"
else
  echo "credentials not found in native keychain"
  exit 1
fi
"""


@pytest.fixture(scope="module")
def kubeconfig() -> str:
    path = os.environ.get("FIXPROOF_IT_KUBECONFIG")
    if not path:
        if os.environ.get("CI"):
            pytest.fail("FIXPROOF_IT_KUBECONFIG is not set; no demo cluster")
        pytest.skip("needs the demo cluster (scripts/demo_cluster.sh up)")
    return path


def exec_kubeconfig(kubeconfig: str, tmp_path: Path, mode: str, api: str) -> tuple[str, str]:
    """The reader kubeconfig with its token moved out to a file an exec plugin reads."""
    config = yaml.safe_load(Path(kubeconfig).read_text(encoding="utf-8"))
    user = config["users"][0]["user"]
    token = user.pop("token")
    secret = tmp_path / "plugin-store"
    secret.write_text(token, encoding="utf-8")
    plugin = tmp_path / "plugin.py"
    plugin.write_text(PLUGIN, encoding="utf-8")
    user["exec"] = {
        "apiVersion": f"client.authentication.k8s.io/{api}",
        "command": sys.executable,
        "args": [str(plugin), mode, str(secret)],
        "interactiveMode": "Never",
    }
    path = tmp_path / "exec.kubeconfig"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    path.chmod(0o600)
    assert token not in path.read_text(encoding="utf-8")
    return str(path), token


@pytest.mark.parametrize("api", ["v1beta1", "v1"])
def test_an_exec_plugin_kubeconfig_reads_the_cluster(
    tmp_path: Path, kubeconfig: str, api: str
) -> None:
    config, token = exec_kubeconfig(kubeconfig, tmp_path, "token", api)
    done = run_verify(tmp_path, config, CONTEXT, ["fixproof-demo"], [OPEN, AUTH], "--json")
    report = report_of(done)
    assert report["summary"] == {"fixed": 2, "still_affected": 3, "unknown": 1}, done.stderr
    assert done.returncode == 1
    check_bundle(tmp_path / "out")
    assert_nowhere(done, tmp_path / "out", token)
    assert token not in Path(config).read_text(encoding="utf-8")  # nothing written back


def test_a_failing_exec_plugin_stops_the_run_with_its_message(
    tmp_path: Path, kubeconfig: str
) -> None:
    config, token = exec_kubeconfig(kubeconfig, tmp_path, "expired", "v1beta1")
    done = run_verify(tmp_path, config, CONTEXT, ["fixproof-demo"], [OPEN, AUTH], "--json")
    assert done.returncode == 3, done.stderr
    assert done.stdout == ""
    assert done.stderr.strip() == (
        f"fixproof: cannot sign in to kubeconfig context '{CONTEXT}': its exec plugin failed: "
        "exec: process returned 1. error: the SSO session has expired; sign in again"
    )
    assert not (tmp_path / "out").exists()  # no evidence from a run that read nothing
    assert token not in done.stderr


@pytest.mark.parametrize("where", ["credHelpers", "credsStore"])
def test_a_credential_helper_opens_the_private_registry_to_every_tool(
    tmp_path: Path, kubeconfig: str, where: str
) -> None:
    login = Path(kubeconfig).parent / "docker" / "config.json"  # demo_cluster.sh's docker login
    auth = json.loads(login.read_text(encoding="utf-8"))["auths"][AUTH]["auth"]
    username, password = base64.b64decode(auth).decode().split(":", 1)
    answer = tmp_path / "helper-answer.json"
    answer.write_text(
        json.dumps({"ServerURL": AUTH, "Username": username, "Secret": password}),
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    helper = bin_dir / "docker-credential-fixproof-test"
    helper.write_text(HELPER.format(registry=AUTH, answer=answer), encoding="utf-8")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    docker_config = tmp_path / "docker-config"
    docker_config.mkdir()
    named = {"credHelpers": {AUTH: "fixproof-test"}} if where == "credHelpers" else {}
    store = {"credsStore": "fixproof-test"} if where == "credsStore" else {}
    (docker_config / "config.json").write_text(json.dumps({**named, **store}), encoding="utf-8")
    log = tmp_path / "helper.log"
    done = run_verify(
        tmp_path, kubeconfig, CONTEXT, ["fixproof-demo"], [OPEN, AUTH], "--json",
        docker_config=docker_config,
        env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "FIXPROOF_HELPER_LOG": str(log)},
    )  # fmt: skip
    report = report_of(done)
    private = by_owner(report)["partner-gateway"]
    assert private["verdict"] == "fixed", private["reason"]
    assert report["summary"] == {"fixed": 3, "still_affected": 3, "unknown": 0}
    asked = [line for line in log.read_text(encoding="utf-8").splitlines() if line == f"get {AUTH}"]
    assert len(asked) >= 3, asked  # crane lists the platforms, then Syft and Grype read it
    check_bundle(tmp_path / "out")
    assert_nowhere(done, tmp_path / "out", password)
