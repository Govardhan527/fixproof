"""The release gate (ADR-0012 items 1 to 3): is any CVE marked closed back in a built image?

For every CVE in `closed.yaml` it runs both methods on the image and the verdict rule, exactly
as `verify` does, on every platform of a registry image (ADR-0014). The image is a registry
reference pinned by digest (its registry must be in `closed.yaml`), or a just-built image named
with an explicit source: `docker:NAME[:TAG]`, `docker-archive:PATH` or `oci-archive:PATH`, which
is one platform. Each tool reads each platform once however many CVEs are closed. If the two
tools read different images (a tag moved between them, say), nothing can be proven and the
verdict is `unknown`.

Exit codes: 0 every closed CVE proven gone; 1 at least one is back; 2 none back but at least one
could not be proven, with the reason; 3 bad input (the CLI).
"""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue

from fixproof.bundle import Summary, summarise
from fixproof.check import check_platform, finish
from fixproof.errors import FixproofError
from fixproof.inputs import ClosedFile
from fixproof.kev import Catalogue, Kev, Unavailable
from fixproof.model import (
    Asset,
    BuildAsset,
    Contract,
    CveId,
    ImageAsset,
    ImageRef,
    NotChecked,
    Text,
    Verdict,
)
from fixproof.platforms import plan
from fixproof.tools import Runner, ToolRun, run_tool

GATE_VERSION: Literal["2.0.0"] = "2.0.0"  # 2.0.0: per-platform reads and verdicts (ADR-0014)
DAEMON, ARCHIVES = "docker:", ("docker-archive:", "oci-archive:")


class GateError(FixproofError):
    """The image argument cannot be gated."""


class PlatformLine(Contract):
    platform: Text
    digest: str
    verdict: Verdict


class GateLine(Contract):
    cve: CveId
    verdict: Verdict
    reason: Text
    kev: Kev
    platforms: tuple[PlatformLine, ...] = Field(
        default=(), description="The CVE's verdict on each platform checked."
    )


class PlatformRead(Contract):
    platform: Text
    digest: str
    scanned: dict[str, dict[str, str]] = Field(
        description="Per tool: the image ID, manifest digest and platform it read."
    )


class GateResult(Contract):
    """`fixproof gate --json` (format `gate-result`, 2.0.0)."""

    schema_version: Literal["2.0.0"]
    image: Text = Field(description="The image as given on the command line.")
    platforms: tuple[PlatformRead, ...] = Field(description="What was read, per platform.")
    not_checked: tuple[NotChecked, ...] = ()
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


def run_gate(
    closed: ClosedFile,
    image: str,
    kev_catalogue: Catalogue | Unavailable,
    run: Runner = run_tool,
) -> GateResult:
    asset = gate_asset(image, closed)
    run = once_per_call(run)
    platforms = plan(asset, closed.platforms, run)
    lines, verdicts, tools = [], [], []
    reads: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
    for entry in closed.closed:
        checks = [check_platform(asset, target, entry.fix, run) for target in platforms.targets]
        assessment = finish(asset, platforms, checks)
        verdict = assessment.verdict
        for outcome in assessment.outcomes:
            if outcome.tool and outcome.tool not in tools:
                tools.append(outcome.tool)
            if outcome.scanned:
                read = reads.setdefault((outcome.platform, outcome.digest), {})
                read[outcome.result.method.value] = dict(outcome.scanned)
        verdicts.append(verdict)
        lines.append(
            GateLine(
                cve=entry.cve,
                verdict=verdict.verdict,
                reason=verdict.reason,
                kev=kev_catalogue.status(entry.cve),
                platforms=tuple(
                    PlatformLine(platform=p.platform, digest=p.digest, verdict=p.verdict)
                    for p in verdict.platforms
                ),
            )
        )
    return GateResult(
        schema_version=GATE_VERSION,
        image=image,
        platforms=tuple(
            PlatformRead(platform=platform, digest=digest, scanned=scanned)
            for (platform, digest), scanned in reads.items()
        ),
        not_checked=platforms.not_checked,
        tools=tuple(tools),
        summary=summarise(verdicts),
        results=tuple(lines),
    )
