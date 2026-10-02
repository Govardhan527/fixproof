"""Verifying a scope (ADR-0007, ADR-0010): images and cluster workloads.

Every distinct image digest is scanned once with both methods. An image named in `scope.yaml`
gets its own verdict; every workload running an image takes that image's verdict and shares its
evidence. A workload whose image cannot be resolved, or comes from a registry outside the
allowlist, is `unknown` with the reason, and its image is never read.
"""

from collections.abc import Callable

from fixproof.bundle import Assessment
from fixproof.inputs import FixFile, ScopeFile
from fixproof.inventory import KubernetesSource, PodSource, inventory
from fixproof.methods import grype, sbom_version
from fixproof.model import AssetVerdict, ImageAsset, ImageRef, Verdict
from fixproof.tools import Runner, run_tool
from fixproof.verdict import combine


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
) -> list[Assessment]:
    """Images in the order `scope.yaml` lists them, then each cluster's workloads."""
    scans: dict[str, Assessment] = {}

    def scanned(image: ImageRef) -> Assessment:
        if image.reference not in scans:
            scans[image.reference] = _scan(image, fix, run)
        return scans[image.reference]

    assessments = [scanned(image) for image in scope.image_refs]
    factory = source_factory or KubernetesSource
    for cluster in scope.clusters:
        for workload in inventory(cluster, factory):
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
                found = scanned(image)
                verdict = found.verdict.model_copy(update={"asset": asset})
                assessments.append(Assessment(verdict, found.outcomes))
    return assessments
