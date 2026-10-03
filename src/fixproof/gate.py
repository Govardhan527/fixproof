"""The release gate (ADR-0012 items 1 to 3): is any CVE marked closed back in a built image?

For every CVE in `closed.yaml` it runs both methods on the image and the verdict rule, exactly
as `verify` does. The image is a registry reference pinned by digest (its registry must be in
`closed.yaml`), or a just-built image named with an explicit source: `docker:NAME[:TAG]`,
`docker-archive:PATH` or `oci-archive:PATH`. Each tool reads the image once however many CVEs
are closed. If the two tools read different images (a tag moved between them, say), nothing can
be proven and every verdict is `unknown`.

Exit codes: 0 every closed CVE proven gone; 1 at least one is back; 2 none back but at least one
could not be proven, with the reason; 3 bad input (the CLI).
"""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue

from fixproof.bundle import Summary, summarise
from fixproof.errors import FixproofError
from fixproof.inputs import ClosedFile
from fixproof.kev import Catalogue, Kev, Unavailable
from fixproof.methods import MethodOutcome, grype, sbom_version
from fixproof.model import (
    Asset,
    AssetVerdict,
    BuildAsset,
    Contract,
    CveId,
    ImageAsset,
    ImageRef,
    Text,
    Verdict,
)
from fixproof.tools import Runner, ToolRun, run_tool
from fixproof.verdict import combine

GATE_VERSION: Literal["1.0.0"] = "1.0.0"
DAEMON, ARCHIVES = "docker:", ("docker-archive:", "oci-archive:")


class GateError(FixproofError):
    """The image argument cannot be gated."""


class GateLine(Contract):
    cve: CveId
    verdict: Verdict
    reason: Text
    kev: Kev


class GateResult(Contract):
    """`fixproof gate --json` (format `gate-result`, 1.0.0)."""

    schema_version: Literal["1.0.0"]
    image: Text = Field(description="The image as given on the command line.")
    scanned: dict[str, dict[str, str]] = Field(
        description="Per tool: the image ID, manifest digest and platform it read."
    )
    tools: tuple[dict[str, JsonValue], ...]
    summary: Summary
    results: tuple[GateLine, ...]


def gate_asset(image: str, closed: ClosedFile) -> Asset:
    """The asset for `--image`, or GateError saying what is accepted."""
    if image.startswith(DAEMON):
        if not image.removeprefix(DAEMON):
            raise GateError("docker: needs an image name, e.g. docker:app:ci")
        return BuildAsset(source=image)
    for scheme in ARCHIVES:
        if image.startswith(scheme):
            path = Path(image.removeprefix(scheme))
            if not path.is_file():
                raise GateError(f"{image}: no such file")
            return BuildAsset(source=image)
    try:
        ref = ImageRef.parse(image.removeprefix("registry:"))
    except ValueError as exc:
        raise GateError(
            f"{exc}. Give a registry image pinned by digest, or a local build as "
            "docker:NAME[:TAG], docker-archive:PATH or oci-archive:PATH"
        ) from exc
    if ref.registry not in closed.registries:
        raise GateError(f"registry {ref.registry} is not in closed.yaml's registries")
    return ImageAsset(image=ref)


def once_per_call(run: Runner) -> Runner:
    """Run each tool once per argument list, however many CVEs ask for the same output."""
    seen: dict[tuple[str, tuple[str, ...]], ToolRun] = {}

    def cached(name: str, args: Sequence[str], env: Mapping[str, str]) -> ToolRun:
        key = (name, tuple(args))
        if key not in seen:
            seen[key] = run(name, args, env)
        return seen[key]

    return cached


def _same_image(outcomes: Sequence[MethodOutcome]) -> str | None:
    """Why the tools' reads cannot be trusted together, or None if they read one image."""
    ids = {o.scanned["image_id"] for o in outcomes if o.scanned.get("image_id")}
    if len(ids) > 1:
        return f"the two tools read different images ({', '.join(sorted(ids))})"
    return None


def run_gate(
    closed: ClosedFile,
    image: str,
    kev_catalogue: Catalogue | Unavailable,
    run: Runner = run_tool,
) -> GateResult:
    asset = gate_asset(image, closed)
    run = once_per_call(run)
    lines, verdicts, tools, scanned = [], [], [], {}
    for entry in closed.closed:
        by_grype = grype.assess(asset, entry.cve, run)
        by_sbom = sbom_version.assess(asset, entry.fix, run)
        verdict = combine(asset, by_grype.result, by_sbom.result)
        mismatch = _same_image((by_grype, by_sbom))
        if mismatch is not None:
            verdict = AssetVerdict(asset=asset, verdict=Verdict.UNKNOWN, reason=mismatch)
        for outcome in (by_grype, by_sbom):
            if outcome.tool and outcome.tool not in tools:
                tools.append(outcome.tool)
            if outcome.scanned:
                scanned[outcome.result.method.value] = dict(outcome.scanned)
        verdicts.append(verdict)
        status = kev_catalogue.status(entry.cve)
        lines.append(
            GateLine(cve=entry.cve, verdict=verdict.verdict, reason=verdict.reason, kev=status)
        )
    return GateResult(
        schema_version=GATE_VERSION,
        image=image,
        scanned=scanned,
        tools=tuple(tools),
        summary=summarise(verdicts),
        results=tuple(lines),
    )
