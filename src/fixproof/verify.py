"""Verifying images (ADR-0007): both methods on every image in scope, then the verdict rule."""

from fixproof.bundle import Assessment
from fixproof.inputs import FixFile, ScopeFile
from fixproof.methods import grype, sbom_version
from fixproof.model import ImageAsset
from fixproof.tools import Runner, run_tool
from fixproof.verdict import combine


def assess_images(fix: FixFile, scope: ScopeFile, run: Runner = run_tool) -> list[Assessment]:
    """One assessment per image in `scope.yaml`, in the order listed there."""
    assessments = []
    for image in scope.image_refs:
        asset = ImageAsset(image=image)
        by_grype = grype.assess(asset, fix.cve, run)
        by_sbom = sbom_version.assess(asset, fix, run)
        verdict = combine(asset, by_grype.result, by_sbom.result)
        assessments.append(Assessment(verdict, (by_grype, by_sbom)))
    return assessments
