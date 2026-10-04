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

import hashlib
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, JsonValue

from fixproof import __version__
from fixproof.bundle import Summary, check_output_dir, manifest_of, raw_part, summarise
from fixproof.canonical import iso, to_json
from fixproof.check import check_platform, finish
from fixproof.errors import FixproofError
from fixproof.inputs import ClosedFile
from fixproof.kev import Catalogue, Kev, Unavailable
from fixproof.methods import MethodOutcome
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
    keep: list[MethodOutcome] | None = None,
) -> GateResult:
    """The gate's result; `keep`, when given, receives every method outcome (ADR-0016)."""
    asset = gate_asset(image, closed)
    run = once_per_call(run)
    platforms = plan(asset, closed.platforms, run)
    lines, verdicts, tools = [], [], []
    reads: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
    for entry in closed.closed:
        checks = [check_platform(asset, target, entry.fix, run) for target in platforms.targets]
        assessment = finish(asset, platforms, checks)
        verdict = assessment.verdict
        if keep is not None:
            keep.extend(assessment.outcomes)
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


# ADR-0016: `gate --out DIR` keeps the decision as evidence (format `gate-bundle`, 1.0.0)
GATE_BUNDLE_VERSION: Literal["1.0.0"] = "1.0.0"


class RawFile(Contract):
    platform: Text
    digest: str
    method: Text
    path: Text


class GateBundle(Contract):
    """`gate.json` in `gate --out`: the decision, what it was made from, and its raw files."""

    schema_version: Literal["1.0.0"]
    fixproof_version: Text
    started: Text
    finished: Text
    closed_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    raw: tuple[RawFile, ...] = Field(description="Each tool's sanitised output, per platform.")
    result: GateResult


def write_gate_bundle(
    out: Path,
    *,
    result: GateResult,
    outcomes: Sequence[MethodOutcome],
    closed_bytes: bytes,
    started: datetime,
    finished: datetime,
    tool_version: str = __version__,
) -> GateBundle:
    """Write `gate.json`, `raw/` and `manifest.json` to `out`, which must be new or empty."""
    check_output_dir(out)
    names = [p.platform for p in result.platforms]
    files: dict[str, bytes] = {}
    raw: list[RawFile] = []
    for outcome in outcomes:  # the tools ran once per platform; every closed CVE shares it
        method = outcome.result.method.value
        if outcome.raw is None or any(
            (r.platform, r.digest, r.method) == (outcome.platform, outcome.digest, method)
            for r in raw
        ):
            continue
        path = f"raw/{raw_part(outcome.platform, outcome.digest, names)}{method}.json"
        files[path] = to_json(outcome.raw)
        raw.append(
            RawFile(platform=outcome.platform, digest=outcome.digest, method=method, path=path)
        )
    record = GateBundle(
        schema_version=GATE_BUNDLE_VERSION,
        fixproof_version=tool_version,
        started=iso(started),
        finished=iso(finished),
        closed_sha256=hashlib.sha256(closed_bytes).hexdigest(),
        raw=tuple(raw),
        result=result,
    )
    files["gate.json"] = to_json(record.model_dump(mode="json"))
    files["manifest.json"] = to_json(manifest_of(files).model_dump(mode="json"))
    (out / "raw").mkdir(parents=True, exist_ok=True)
    for path, data in files.items():
        (out / path).write_bytes(data)
    return record
