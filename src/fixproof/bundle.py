"""The evidence bundle (ADR-0007 item 7): formats `bundle` 1.1.0 and `manifest` 1.0.0.

    <out>/openvex.json            the VEX document (ADR-0005)
    <out>/bundle.json             run, inputs, tool versions, every asset's verdict and results
    <out>/raw/NNN-<method>.json   each method's tool output, sanitised (fixproof.sanitize)
    <out>/manifest.json           SHA-256 and size of every other file, sorted by path

Workloads running the same image share its method outcomes, so its raw files are written once,
numbered after the first asset that used them, and every such asset points at them (ADR-0010).

Every file is canonical JSON. `<out>` must not exist or must be empty: a bundle is never
overwritten, so evidence once written stays as it was.
"""

import hashlib
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, JsonValue

from fixproof import __version__
from fixproof.canonical import iso, to_json
from fixproof.errors import FixproofError
from fixproof.methods import MethodOutcome
from fixproof.model import Asset, AssetVerdict, Contract, CveId, MethodResult, Text, Verdict
from fixproof.validation import check_openvex

BUNDLE_VERSION: Literal["1.1.0"] = "1.1.0"  # 1.1.0: workloads carry `owner` (ADR-0010)
MANIFEST_VERSION: Literal["1.0.0"] = "1.0.0"
Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class OutputExistsError(FixproofError):
    """The output directory already holds files; fixproof never overwrites evidence."""


@dataclass(frozen=True)
class Assessment:
    """One asset's verdict with the method outcomes behind it."""

    verdict: AssetVerdict
    outcomes: tuple[MethodOutcome, ...] = ()


class Inputs(Contract):
    fix_sha256: Sha256
    scope_sha256: Sha256


class Summary(Contract):
    fixed: int
    still_affected: int
    unknown: int


class AssetRecord(Contract):
    index: int = Field(ge=1)
    asset: Asset
    verdict: Verdict
    reason: Text
    results: tuple[MethodResult, ...]
    scanned: dict[str, dict[str, str]] = Field(
        description="Per method: the manifest digest and platform the tool scanned."
    )


class Bundle(Contract):
    schema_version: Literal["1.1.0"]
    fixproof_version: Text
    started: Text
    finished: Text
    cve: CveId
    inputs: Inputs
    tools: tuple[dict[str, JsonValue], ...] = Field(
        description="Each distinct tool and data version used, e.g. Syft and its JSON schema, "
        "Grype and its DB schema, build time and source."
    )
    summary: Summary
    assets: tuple[AssetRecord, ...]


class ManifestEntry(Contract):
    path: Text
    sha256: Sha256
    size: int = Field(ge=0)


class Manifest(Contract):
    schema_version: Literal["1.0.0"]
    files: tuple[ManifestEntry, ...]


def summarise(verdicts: Sequence[AssetVerdict]) -> Summary:
    counts = Counter(item.verdict for item in verdicts)
    return Summary(
        fixed=counts[Verdict.FIXED],
        still_affected=counts[Verdict.STILL_AFFECTED],
        unknown=counts[Verdict.UNKNOWN],
    )


def check_output_dir(out: Path) -> None:
    """Raise OutputExistsError unless `out` is missing or an empty directory."""
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise OutputExistsError(f"{out} already exists and is not empty; choose a new --out")


def write_bundle(
    out: Path,
    *,
    cve: str,
    fix_bytes: bytes,
    scope_bytes: bytes,
    assessments: Sequence[Assessment],
    vex: dict[str, Any],
    started: datetime,
    finished: datetime,
    tool_version: str = __version__,
) -> Bundle:
    """Write the whole bundle to `out` and return the bundle record."""
    check_openvex(vex)
    check_output_dir(out)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    files: dict[str, bytes] = {"openvex.json": to_json(vex)}
    records, tools = [], []
    raw_refs: dict[int, str] = {}  # id() of a shared outcome -> its raw file
    for index, assessment in enumerate(assessments, start=1):
        results, scanned = [], {}
        for outcome in assessment.outcomes:
            method = outcome.result.method.value
            raw_ref = raw_refs.get(id(outcome))
            if raw_ref is None and outcome.raw is not None:
                raw_ref = raw_refs[id(outcome)] = f"raw/{index:03d}-{method}.json"
                files[raw_ref] = to_json(outcome.raw)
            results.append(outcome.result.model_copy(update={"raw_ref": raw_ref}))
            if outcome.scanned:
                scanned[method] = dict(outcome.scanned)
            if outcome.tool and outcome.tool not in tools:
                tools.append(outcome.tool)
        verdict = assessment.verdict
        records.append(
            AssetRecord(
                index=index,
                asset=verdict.asset,
                verdict=verdict.verdict,
                reason=verdict.reason,
                results=tuple(results),
                scanned=scanned,
            )
        )
    bundle = Bundle(
        schema_version=BUNDLE_VERSION,
        fixproof_version=tool_version,
        started=iso(started),
        finished=iso(finished),
        cve=cve,
        inputs=Inputs(
            fix_sha256=hashlib.sha256(fix_bytes).hexdigest(),
            scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
        ),
        tools=tuple(sorted(tools, key=lambda tool: to_json(tool))),
        summary=summarise([a.verdict for a in assessments]),
        assets=tuple(records),
    )
    files["bundle.json"] = to_json(bundle.model_dump(mode="json"))
    manifest = Manifest(
        schema_version=MANIFEST_VERSION,
        files=tuple(
            ManifestEntry(path=path, sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            for path, data in sorted(files.items())
        ),
    )
    files["manifest.json"] = to_json(manifest.model_dump(mode="json"))
    for path, data in files.items():
        (out / path).write_bytes(data)
    return bundle
