"""Verifying a scope (ADR-0007, ADR-0010, ADR-0011): images and cluster workloads.

Every distinct image digest is scanned once with both methods, up to `jobs` images at a time.
An image named in `scope.yaml` gets its own verdict; every workload running an image takes that
image's verdict and shares its evidence. A workload whose image cannot be resolved, or comes
from a registry outside the allowlist, is `unknown` with the reason, and its image is never
read. The result is the same, in the same order, for any `jobs`.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from fixproof.bundle import Assessment
from fixproof.inputs import FixFile, ScopeFile
from fixproof.inventory import KubernetesSource, PodSource, inventory
from fixproof.methods import grype, sbom_version
from fixproof.model import AssetVerdict, ImageAsset, ImageRef, Verdict
from fixproof.tools import Runner, run_tool
from fixproof.verdict import combine

DEFAULT_JOBS = 4  # ADR-0011: about 1.2 GB at peak (SPEC_NOTES §12, measured)


def _scan(image: ImageRef, fix: FixFile, run: Runner) -> Assessment:
    asset = ImageAsset(image=image)
    by_grype = grype.assess(asset, fix.cve, run)
    by_sbom = sbom_version.assess(asset, fix, run)
    return Assessment(combine(asset, by_grype.result, by_sbom.result), (by_grype, by_sbom))


def assess(
    fix: FixFile,
    scope: ScopeFile,
    run: Runner = run_tool,
    source_factory: Callable[[str], PodSource] | None = None,
    jobs: int = DEFAULT_JOBS,
) -> list[Assessment]:
    """Images in the order `scope.yaml` lists them, then each cluster's workloads."""
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    factory = source_factory or KubernetesSource
    workloads = [w for cluster in scope.clusters for w in inventory(cluster, factory)]

    # Each distinct image to read, first come first: listed images, then allowlisted workloads
    to_scan = {image.reference: image for image in scope.image_refs}
    for workload in workloads:
        image = workload.asset.image
        if workload.problem is None and image is not None and image.registry in scope.registries:
            to_scan.setdefault(image.reference, image)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {ref: pool.submit(_scan, image, fix, run) for ref, image in to_scan.items()}
        scans = {ref: future.result() for ref, future in futures.items()}

    assessments = [scans[image.reference] for image in scope.image_refs]
    for workload in workloads:
        asset, image = workload.asset, workload.asset.image
        if workload.problem is not None or image is None:
            reason = workload.problem or "image digest not resolved"
            assessments.append(
                Assessment(AssetVerdict(asset=asset, verdict=Verdict.UNKNOWN, reason=reason))
            )
        elif image.registry not in scope.registries:
            reason = f"registry not in scope: {image.registry}; fixproof did not read the image"
            assessments.append(
                Assessment(AssetVerdict(asset=asset, verdict=Verdict.UNKNOWN, reason=reason))
            )
        else:
            found = scans[image.reference]
            verdict = found.verdict.model_copy(update={"asset": asset})
            assessments.append(Assessment(verdict, found.outcomes))
    return assessments
