"""Live checks: real public images, real Syft and Grype, the live Grype DB (ADR-0008).

Each case pins an image by digest and states its expected verdict with an independent source for
it (SPEC_NOTES §19), so a changed verdict means the tools, the advisory data or fixproof changed.
Each image is checked on linux/amd64 and linux/arm64 (ADR-0014): a distribution or a pinned
build ships the same package versions on both, so each platform must get the expected verdict.
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


def _hub(repository: str, digest: str) -> str:
    return f"docker.io/library/{repository}@sha256:{digest}"


OPENSSL_ALPINE_CVE = "CVE-2023-5363"  # Alpine secdb v3.18: openssl 3.1.4-r0 (SPEC_NOTES §19)
OPENSSL_RHEL_CVE = "CVE-2023-0286"  # Red Hat: openssl-1:3.0.1-47.el9_1, EUS 1:3.0.1-46.el9_0
LOG4SHELL_CVE = "CVE-2021-44228"  # in CISA KEV; GHSA-jfh8-c2jp-5v3q: fixed 2.15.0
ALPINE_3_18_0 = _hub("alpine", "02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11")
ALPINE_3_22 = _hub("alpine", "5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8")
ALMA_9_0 = _hub("almalinux", "a95a7766fd056b35f72f7b7f7301bcd46e40a6eecd9017e9c41cb4bf22ecb28b")
ALMA_9 = _hub("almalinux", "3a3fa7f043b142bc8008c8b308d39b47d2c84008addcd52f9f9a7a82d2a90474")
LOG4SHELL_APP = (  # its build pins spring-boot-starter-log4j2 2.6.1, which pins log4j 2.14.1
    "ghcr.io/christophetd/log4shell-vulnerable-app"
    "@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929"
)

SINGLE_PLATFORM = {LOG4SHELL_APP}  # one linux/amd64 manifest, no index (SPEC_NOTES §20)

OPENSSL_ALPINE_FIX = f"""\
schema_version: "1.0.0"
cve: {OPENSSL_ALPINE_CVE}
packages:
  - ecosystem: apk
    namespace: alpine
    name: libcrypto3
    fixed_version: "3.1.4-r0"
  - ecosystem: apk
    namespace: alpine
    name: libssl3
    fixed_version: "3.1.4-r0"
"""
OPENSSL_RHEL_FIX = f"""\
schema_version: "1.0.0"
cve: {OPENSSL_RHEL_CVE}
packages:
  - ecosystem: rpm
    namespace: almalinux
    name: openssl-libs
    fixed_version: "1:3.0.1-47.el9_1"
    fixed_vers: "vers:rpm/>=1:3.0.1-46.el9_0|<1:3.0.1-47"
  - ecosystem: rpm
    namespace: almalinux
    name: openssl
    fixed_version: "1:3.0.1-47.el9_1"
    fixed_vers: "vers:rpm/>=1:3.0.1-46.el9_0|<1:3.0.1-47"
"""
LOG4SHELL_FIX = f"""\
schema_version: "1.0.0"
cve: {LOG4SHELL_CVE}
packages:
  - ecosystem: maven
    namespace: org.apache.logging.log4j
    name: log4j-core
    fixed_version: "2.15.0"
    fixed_vers: "vers:maven/>=2.3.1|<2.4|>=2.12.2|<2.13"
"""

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


PLATFORMS = ("linux/amd64", "linux/arm64")


def verify(
    tmp_path: Path, fix: str, cve: str, images: list[str], registries: str = "docker.io"
) -> tuple[int, dict[str, Any], Path]:
    (tmp_path / "fix.yaml").write_text(fix, encoding="utf-8")
    (tmp_path / "scope.yaml").write_text(
        f'schema_version: "1.1.0"\nregistries: [{registries}]\n'
        f"platforms: [{', '.join(PLATFORMS)}]\nimages:\n"
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
    """Each image's verdict and reason, after checking every platform got that same verdict.

    An index is checked on linux/amd64 and linux/arm64 (Docker Hub names the latter
    linux/arm64/v8 for some images); a single-platform image is checked as the one it is.
    """
    both = ({"linux/amd64", "linux/arm64"}, {"linux/amd64", "linux/arm64/v8"})
    for item in report["assets"]:
        checked = {p["platform"]: p["verdict"] for p in item["platforms"]}
        expected = ({"linux/amd64"},) if item["asset"] in SINGLE_PLATFORM else both
        assert set(checked) in expected, (item["asset"], checked, item["not_checked"])
        assert set(checked.values()) == {item["verdict"]}, (item["asset"], item["reason"])
    return {item["asset"]: (item["verdict"], item["reason"]) for item in report["assets"]}


def test_requests_fix_across_certbot_releases(tmp_path: Path) -> None:
    code, report, out = verify(tmp_path, REQUESTS_FIX, REQUESTS_CVE, list(CERTBOT.values()))
    found = verdicts(report)
    assert found[CERTBOT["v2.6.0"]][0] == "still_affected", found[CERTBOT["v2.6.0"]][1]
    assert found[CERTBOT["v2.7.0"]][0] == "fixed", found[CERTBOT["v2.7.0"]][1]
    assert found[CERTBOT["v5.8.0"]][0] == "fixed", found[CERTBOT["v5.8.0"]][1]
    assert "requests 2.28.2" in found[CERTBOT["v2.6.0"]][1]
    assert "requests 2.31.0" in found[CERTBOT["v2.7.0"]][1]
    assert report["kev"]["status"] == "not_listed"  # the live CISA feed
    assert code == 1
    check_openvex(json.loads((out / "openvex.json").read_text()))


def test_glibc_kev_cve_on_debian_images(tmp_path: Path) -> None:
    """Debian 12.0 still has libc6 2.36-9; Debian 12.15 has the fixed 2.36-9+deb12uN."""
    code, report, _ = verify(tmp_path, GLIBC_FIX, GLIBC_CVE, [DEBIAN_12_0, PYTHON_SLIM])
    found = verdicts(report)
    old_verdict, old_reason = found[DEBIAN_12_0]
    assert old_verdict == "still_affected", old_reason
    assert "linux/amd64: both methods find the vulnerable component" in old_reason
    assert "libc6 2.36-9 at" in old_reason
    new_verdict, new_reason = found[PYTHON_SLIM]
    assert new_verdict == "fixed", new_reason
    assert "libc6 2.36-9+deb12u" in new_reason
    assert report["kev"]["status"] == "listed"  # "Looney Tunables" is in CISA KEV
    assert report["kev"]["entry"]["date_added"] == "2023-11-21"
    assert code == 1


def test_openssl_on_alpine(tmp_path: Path) -> None:
    code, report, _ = verify(
        tmp_path, OPENSSL_ALPINE_FIX, OPENSSL_ALPINE_CVE, [ALPINE_3_18_0, ALPINE_3_22]
    )
    found = verdicts(report)
    assert found[ALPINE_3_18_0][0] == "still_affected", found[ALPINE_3_18_0][1]
    assert "libcrypto3 3.1.0-r4 at" in found[ALPINE_3_18_0][1]
    assert found[ALPINE_3_22][0] == "fixed", found[ALPINE_3_22][1]
    assert code == 1


def test_openssl_on_almalinux_with_an_rpm_epoch(tmp_path: Path) -> None:
    code, report, _ = verify(tmp_path, OPENSSL_RHEL_FIX, OPENSSL_RHEL_CVE, [ALMA_9_0, ALMA_9])
    found = verdicts(report)
    assert found[ALMA_9_0][0] == "still_affected", found[ALMA_9_0][1]
    assert "openssl-libs 1:3.0.1-43.el9_0 at" in found[ALMA_9_0][1]
    assert found[ALMA_9][0] == "fixed", found[ALMA_9][1]
    assert code == 1


def test_log4shell_in_a_spring_boot_jar(tmp_path: Path) -> None:
    code, report, _ = verify(
        tmp_path, LOG4SHELL_FIX, LOG4SHELL_CVE, [LOG4SHELL_APP], registries="ghcr.io"
    )
    verdict, reason = verdicts(report)[LOG4SHELL_APP]
    assert verdict == "still_affected", reason
    assert "log4j-core 2.14.1" in reason
    kev = report["kev"]
    assert kev["status"] == "listed"
    assert kev["entry"]["known_ransomware_campaign_use"] == "Known"
    assert code == 1
