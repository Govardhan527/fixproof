"""The SUCCESS TEST, end to end, on the demo cluster (ADR-0013 item 1). `make demo` runs it.

    success_test.py --work .demo

`--work` is the directory `scripts/demo_cluster.sh up` filled (reader.kubeconfig,
fixture-images.json). Each step runs the installed `fixproof` command as a user would, with the
read-only cluster token and no registry credentials, then checks the project plan's criteria:

1. `fixproof verify` on the six workloads reports exactly 2 fixed, 3 still_affected (with image
   digests and pod names) and 1 unknown with the reason;
2. the OpenVEX it wrote validates against the pinned schema, with no `not_affected`;
3. `fixproof gate` exits non-zero on a built image that brings the closed CVE back, and zero on
   one that does not.

It prints PASS or FAIL per step and exits 1 if any step fails.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fixproof.validation import openvex_errors

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "examples" / "scope" / "kind-demo.yaml"
CVE = "CVE-2023-32681"
FIX = f"""\
schema_version: "1.0.0"
cve: {CVE}
packages:
  - ecosystem: pypi
    name: requests
    fixed_version: "2.31.0"
"""
CLOSED = f"""\
schema_version: "1.0.0"
closed:
  - cve: {CVE}
    packages:
      - ecosystem: pypi
        name: requests
        fixed_version: "2.31.0"
"""
EXPECTED = {"fixed": 2, "still_affected": 3, "unknown": 1}
POD = "kind-fixproof/fixproof-demo/"


def check_step1(code: int, report: dict[str, Any]) -> list[str]:
    """Problems with step 1, or none."""
    problems = []
    if report.get("summary") != EXPECTED:
        problems.append(f"summary is {report.get('summary')}, expected {EXPECTED}")
    if code != 1:
        problems.append(f"exit code {code}, expected 1 (still_affected present)")
    for item in report.get("assets", []):
        workload = item.get("workload") or ""
        if not workload.startswith(POD):
            problems.append(f"{workload or item.get('asset')}: not a demo workload")
        elif item["verdict"] in {"fixed", "still_affected"} and "@sha256:" not in (
            item.get("asset") or ""
        ):
            problems.append(f"{workload}: no image digest")
        elif item["verdict"] == "unknown" and not item.get("reason"):
            problems.append(f"{workload}: unknown without a reason")
    return problems


def check_step2(vex: dict[str, Any]) -> list[str]:
    problems = [f"OpenVEX schema: {error}" for error in openvex_errors(vex)]
    if any(s.get("status") == "not_affected" for s in vex.get("statements", [])):
        problems.append("a not_affected statement was written")
    return problems


def check_step3(back: int, clean: int) -> list[str]:
    problems = []
    if back == 0:
        problems.append("gate exited 0 on an image that brings the closed CVE back")
    if clean != 0:
        problems.append(f"gate exited {clean} on an image without the CVE, expected 0")
    return problems


def fixproof(args: Sequence[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    command = shutil.which("fixproof")
    if command is None:
        raise SystemExit("fixproof is not on PATH; run this through `make demo`")
    return subprocess.run([command, *args], capture_output=True, text=True, env=env, check=False)


def report(step: str, problems: list[str]) -> bool:
    print(f"{'PASS' if not problems else 'FAIL'}  {step}")
    for problem in problems:
        print(f"      {problem}")
    return not problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SUCCESS TEST on the demo cluster.")
    parser.add_argument("--work", type=Path, required=True, help="demo_cluster.sh's WORKDIR")
    args = parser.parse_args(argv)
    work = args.work.resolve()
    run = work / "runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    (run / "no-credentials").mkdir(parents=True)
    (run / "fix.yaml").write_text(FIX, encoding="utf-8")
    (run / "closed.yaml").write_text(CLOSED, encoding="utf-8")
    env = {
        **os.environ,
        "KUBECONFIG": str(work / "reader.kubeconfig"),
        "DOCKER_CONFIG": str(run / "no-credentials"),
    }
    images: dict[str, str] = json.loads((work / "fixture-images.json").read_text(encoding="utf-8"))

    verify = fixproof(
        [
            "verify", "--cve", CVE, "--fix", str(run / "fix.yaml"), "--scope", str(SCOPE),
            "--out", str(run / "evidence"), "--author", "fixproof demo", "--json",
        ],
        env,
    )  # fmt: skip
    try:
        result = json.loads(verify.stdout)
    except ValueError:
        result = {}
    for item in result.get("assets", []):
        print(f"      {item['verdict']:<15} {item.get('workload')}  {item.get('asset')}")
    step1 = report(
        "1. verify: 2 fixed, 3 still_affected with digests and pod names, 1 unknown with reason",
        check_step1(verify.returncode, result) if result else [verify.stderr.strip()],
    )
    vex_path = run / "evidence" / "openvex.json"
    vex = json.loads(vex_path.read_text(encoding="utf-8")) if vex_path.is_file() else {}
    step2 = report(
        "2. OpenVEX validates against the pinned schema, no not_affected",
        check_step2(vex) if vex else ["no openvex.json was written"],
    )

    def gate(name: str) -> int:
        image = "docker:" + images[name].split("@", 1)[0] + ":it"  # build_fixtures.py's tag
        done = fixproof(["gate", "--closed", str(run / "closed.yaml"), "--image", image], env)
        print("\n".join(f"      {line}" for line in done.stdout.splitlines()))
        return done.returncode

    step3 = report(
        "3. gate: non-zero when a built image brings the closed CVE back, zero otherwise",
        check_step3(gate("requests-2.30.0"), gate("requests-2.31.0")),
    )
    passed = sum((step1, step2, step3))
    print(
        f"SUCCESS TEST: {'PASS' if passed == 3 else 'FAIL'} ({passed}/3 steps); evidence in {run}"
    )
    return 0 if passed == 3 else 1


if __name__ == "__main__":
    sys.exit(main())
