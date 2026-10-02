"""Live checks: real public images, real Syft and Grype, the live Grype DB (ADR-0008).

Each case pins an image by digest and states its expected verdict with an independent source for
it (SPEC_NOTES §19), so a changed verdict means the tools, the advisory data or fixproof changed.
They read Docker Hub anonymously and run weekly in CI (`.github/workflows/live.yml`) and on demand
(`make live`). Without syft and grype on PATH they skip locally and fail in CI.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from fixproof.validation import check_openvex

pytestmark = pytest.mark.live

REQUESTS_CVE = "CVE-2023-32681"  # requests >= 2.3.0, < 2.31.0 (SPEC_NOTES §17)
GLIBC_CVE = "CVE-2023-4911"  # glibc "Looney Tunables", in CISA KEV (SPEC_NOTES §19)

_CERTBOT = "docker.io/certbot/certbot@sha256:"
CERTBOT = {  # certbot pins requests in tools/requirements.txt at each release tag
    "v2.6.0": _CERTBOT + "92092d214a4eb75d049720d04f7acc50b40ea226d77736bce6a6bf43981b6e86",
    "v2.7.0": _CERTBOT + "68e0f51ce9037d3b022d446772277beb1e9c0fe801e75fbf87db105ab165ad54",
    "v5.8.0": _CERTBOT + "f70ad0adbb7e117f0fe42a63c553f28ea451edabc0148757b6efcd9735acaa20",
}
DEBIAN_12_0 = (  # debian:12.0-slim
    "docker.io/library/debian@sha256:9bd077d2f77c754f4f7f5ee9e6ded9ff1dff92c6dce877754da21b917c122c77"
)
PYTHON_SLIM = (  # python:3.12-slim-bookworm, Debian 12.15 on 2026-10-02
    "docker.io/library/python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3"
)

REQUESTS_FIX = f"""\
schema_version: "1.0.0"
cve: {REQUESTS_CVE}
packages:
  - ecosystem: pypi
    name: requests
    fixed_version: "2.31.0"
"""
GLIBC_FIX = f"""\
schema_version: "1.0.0"
cve: {GLIBC_CVE}
packages:
  - ecosystem: deb
    namespace: debian
    name: libc6
    fixed_version: "2.36-9+deb12u3"
    fixed_vers: "vers:deb/>=2.31-13+deb11u7|<2.32"
  - ecosystem: deb
    namespace: debian
    name: libc-bin
    fixed_version: "2.36-9+deb12u3"
    fixed_vers: "vers:deb/>=2.31-13+deb11u7|<2.32"
"""


@pytest.fixture(scope="module", autouse=True)
def _scanners() -> None:
    missing = [tool for tool in ("syft", "grype") if shutil.which(tool) is None]
    if missing:
        if os.environ.get("CI"):
            pytest.fail(f"{', '.join(missing)} not on PATH; the live setup did not run")
        pytest.skip(f"{', '.join(missing)} not on PATH (see .github/workflows/live.yml)")


def verify(
    tmp_path: Path, fix: str, cve: str, images: list[str]
) -> tuple[int, dict[str, Any], Path]:
    (tmp_path / "fix.yaml").write_text(fix, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(
        'schema_version: "1.0.0"\nregistries: [docker.io]\nimages:\n'
        + "".join(f"  - {image}\n" for image in images),
        encoding="utf-8",
    )
    no_credentials = tmp_path / "docker-config"
    no_credentials.mkdir()
    out = tmp_path / "out"
    done = subprocess.run(
        [
            sys.executable, "-c", "from fixproof.cli import main; main()",
            "verify", "--cve", cve, "--fix", str(tmp_path / "fix.yaml"),
            "--scope", str(tmp_path / "scope.yaml"), "--out", str(out),
            "--author", "fixproof live checks", "--json",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "DOCKER_CONFIG": str(no_credentials)},
        check=False,
        timeout=3600,
    )  # fmt: skip
    assert done.stdout, done.stderr
    return done.returncode, json.loads(done.stdout), out


def verdicts(report: dict[str, Any]) -> dict[str, tuple[str, str]]:
    return {item["asset"]: (item["verdict"], item["reason"]) for item in report["assets"]}


def test_requests_fix_across_certbot_releases(tmp_path: Path) -> None:
    code, report, out = verify(tmp_path, REQUESTS_FIX, REQUESTS_CVE, list(CERTBOT.values()))
    found = verdicts(report)
    assert found[CERTBOT["v2.6.0"]][0] == "still_affected", found[CERTBOT["v2.6.0"]][1]
    assert found[CERTBOT["v2.7.0"]][0] == "fixed", found[CERTBOT["v2.7.0"]][1]
    assert found[CERTBOT["v5.8.0"]][0] == "fixed", found[CERTBOT["v5.8.0"]][1]
    assert "requests 2.28.2" in found[CERTBOT["v2.6.0"]][1]
    assert "requests 2.31.0" in found[CERTBOT["v2.7.0"]][1]
    assert code == 1
    check_openvex(json.loads((out / "openvex.json").read_text()))


def test_glibc_kev_cve_on_debian_images(tmp_path: Path) -> None:
    """Debian 12.0 still has libc6 2.36-9; Debian 12.15 has the fixed 2.36-9+deb12uN."""
    code, report, _ = verify(tmp_path, GLIBC_FIX, GLIBC_CVE, [DEBIAN_12_0, PYTHON_SLIM])
    found = verdicts(report)
    old_verdict, old_reason = found[DEBIAN_12_0]
    assert old_verdict == "still_affected", old_reason
    assert old_reason.startswith("both methods find the vulnerable component")
    assert "libc6 2.36-9 at" in old_reason
    new_verdict, new_reason = found[PYTHON_SLIM]
    assert new_verdict == "fixed", new_reason
    assert "libc6 2.36-9+deb12u" in new_reason
    assert code == 1
