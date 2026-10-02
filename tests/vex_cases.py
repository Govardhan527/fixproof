"""Synthetic verdicts for the VEX tests and the golden files. Nothing here names a real CVE."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import yaml

from fixproof.inputs import FixFile, load_fix
from fixproof.model import AssetVerdict, ImageAsset, ImageRef, Verdict, WorkloadAsset

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = datetime(2026, 10, 2, 8, 0, 0, tzinfo=UTC)
AUTHOR = "Example Vulnerability Management <vm@example.com>"
TOOL_VERSION = "0.0.0"  # fixed, so a version bump does not churn the golden files


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def image(repository: str, registry: str = "localhost:5001") -> ImageRef:
    return ImageRef(registry=registry, repository=repository, digest=digest(repository))


def workload(pod: str, ref: ImageRef | None) -> WorkloadAsset:
    return WorkloadAsset(
        cluster="kind-fixproof", namespace="demo", pod=pod, container="app", image=ref
    )


def example_fix(name: str) -> FixFile:
    path = EXAMPLES / "fix" / f"{name}.yaml"
    return load_fix(path, yaml.safe_load(path.read_text(encoding="utf-8"))["cve"])


WEB = image("fixproof/demo-web")
API = image("fixproof/demo-api")
BATCH = image("fixproof/demo-batch")
WORKER = image("vendor/worker", registry="registry.other.example")

FIXED_REASON = "grype: no match; sbom: libdemo1 1.4.2-1 is in the fixed range"
MIXED = [
    AssetVerdict(asset=workload("web-1", WEB), verdict=Verdict.FIXED, reason=FIXED_REASON),
    AssetVerdict(asset=workload("web-2", WEB), verdict=Verdict.FIXED, reason=FIXED_REASON),
    AssetVerdict(
        asset=workload("api-1", API),
        verdict=Verdict.STILL_AFFECTED,
        reason="grype: match on libdemo1 1.4.1-2; sbom: libdemo1 1.4.1-2 is below 1.4.2-1",
    ),
    AssetVerdict(
        asset=ImageAsset(image=BATCH),
        verdict=Verdict.FIXED,
        reason="grype: no match; sbom: libdemo1 1.2.0-3+deb12u1 is in the fixed range",
    ),
    AssetVerdict(
        asset=workload("worker-1", WORKER),
        verdict=Verdict.UNKNOWN,
        reason="registry not in scope: registry.other.example",
    ),
    AssetVerdict(
        asset=workload("cron-1", None),
        verdict=Verdict.UNKNOWN,
        reason="image digest not resolved: container is waiting (ImagePullBackOff)",
    ),
]
SINGLE_FIXED = [
    AssetVerdict(
        asset=ImageAsset(image=image("fixproof/demo-parser")),
        verdict=Verdict.FIXED,
        reason="grype: no match; sbom: demo-parser 2.31.0 is in the fixed range",
    )
]
# Golden file name -> (fix example, verdicts).
GOLDEN: dict[str, tuple[str, list[AssetVerdict]]] = {
    "mixed": ("backported-deb", MIXED),
    "single-fixed": ("pypi", SINGLE_FIXED),
}
