"""The `fixproof` command line (ADR-0007 item 8).

Exit codes: 0 every asset fixed; 1 any still_affected; 2 no still_affected but any unknown;
3 bad input or usage. Click's own usage errors would exit 2, which means something else here,
so `main` maps them to 3.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from fixproof import __version__, kev
from fixproof.bundle import check_output_dir, summarise, write_bundle
from fixproof.cyclonedx import build_bom
from fixproof.errors import FixproofError
from fixproof.gate import GateLine, GateResult, run_gate, write_gate_bundle
from fixproof.inputs import load_closed, load_fix, load_scope
from fixproof.methods import MethodOutcome
from fixproof.model import AssetVerdict, Verdict, WorkloadAsset
from fixproof.report import verify_summary
from fixproof.verdict import platform_lines
from fixproof.verify import DEFAULT_JOBS, assess
from fixproof.vex import build_document

EXIT_FIXED, EXIT_AFFECTED, EXIT_UNKNOWN, EXIT_USAGE = 0, 1, 2, 3

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help="Proof, asset by asset, that a remediated CVE is actually gone.",
)


def now() -> datetime:
    """The clock. Tests replace it."""
    return datetime.now(UTC)


kev_fetcher: kev.Fetcher = kev.fetch  # how the CISA KEV feed is read; tests replace it


def _version(value: bool) -> None:
    if value:
        typer.echo(f"fixproof {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Print the version."),
    ] = False,
) -> None:
    """fixproof checks a claimed fix for one CVE against images and workloads."""


@app.command()
def verify(
    cve: Annotated[str, typer.Option(help="The CVE id the fix claims to close.")],
    fix: Annotated[Path, typer.Option(help="fix.yaml: the packages and fixed versions.")],
    scope: Annotated[
        Path, typer.Option(help="scope.yaml: registries, images and clusters to check.")
    ],
    out: Annotated[Path, typer.Option(help="New or empty directory for the evidence bundle.")],
    author: Annotated[str, typer.Option(help="Who issues the VEX document (OpenVEX author).")],
    as_json: Annotated[bool, typer.Option("--json", help="Print the summary as JSON.")] = False,
    jobs: Annotated[
        int, typer.Option(min=1, help="How many image platforms to scan at the same time.")
    ] = DEFAULT_JOBS,
) -> None:
    """Check every image and workload in scope with Grype and the SBOM version check, then
    write the VEX and the evidence bundle. Needs syft and grype on PATH and a current Grype DB;
    registry credentials come from the usual Docker config or environment and are never stored.
    Clusters are read through their kubeconfig context, with get and list on pods and
    replicasets only (deploy/kubernetes/fixproof-reader.yaml).
    """
    try:
        fix_file = load_fix(fix, cve)
        scope_file = load_scope(scope)
        check_output_dir(out)
        started = now()
        kev_status = kev.load(started, kev_fetcher).status(cve)
        assessments = assess(fix_file, scope_file, jobs=jobs)
        finished = now()
        verdicts = [a.verdict for a in assessments]
        vex = build_document(fix_file, verdicts, author=author, now=finished)
        write_bundle(
            out,
            cve=cve,
            fix_bytes=fix.read_bytes(),
            scope_bytes=scope.read_bytes(),
            assessments=assessments,
            vex=vex,
            cyclonedx=build_bom(fix_file, verdicts, now=finished),
            started=started,
            finished=finished,
            kev=kev_status,
        )
    except (FixproofError, ValueError) as exc:
        typer.echo(f"fixproof: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    summary = summarise(verdicts)
    if as_json:
        report = verify_summary(cve, str(out), verdicts, kev_status).model_dump(mode="json")
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        for item in verdicts:
            typer.echo(_human(item))
        typer.echo(kev_line(cve, kev_status))
        typer.echo(
            f"{summary.fixed} fixed, {summary.still_affected} still_affected, "
            f"{summary.unknown} unknown; evidence in {out}"
        )
    raise typer.Exit(verdict_exit_code([item.verdict for item in verdicts]))


def _human(item: AssetVerdict) -> str:
    """`verdict  image` or `verdict  cluster/namespace/pod/container  owner` and its image, then
    the reason, each detail line indented under the verdict."""
    asset, pad = item.asset, " " * 16
    image = asset.image.reference if asset.image else "image not resolved"
    if isinstance(asset, WorkloadAsset):
        owner = f"  {asset.owner}" if asset.owner else ""
        head = f"{asset.location}{owner}\n{pad}{image}"
    else:
        head = image
    if len(item.platforms) > 1 or item.not_checked:
        why = f"\n{pad}".join(platform_lines(item.platforms, item.not_checked))
    else:
        why = item.reason
    return f"{item.verdict.value:<15} {head}\n{pad}{why}"


@app.command()
def gate(
    closed: Annotated[
        Path,
        typer.Option(help="closed.yaml: the CVEs marked closed and the fixes that closed them."),
    ],
    image: Annotated[
        str,
        typer.Option(
            help="The built image: a registry image pinned by digest (registry: optional), or "
            "docker:NAME[:TAG], docker-archive:PATH or oci-archive:PATH."
        ),
    ],
    as_json: Annotated[bool, typer.Option("--json", help="Print the result as JSON.")] = False,
    out: Annotated[
        Path | None,
        typer.Option(help="New or empty directory to keep the decision and the tool output in."),
    ] = None,
) -> None:
    """Block a release that brings back a CVE marked closed. Exit 0 when every closed CVE is
    proven gone from the image, 1 when one is back, 2 when one cannot be proven either way (the
    reason is printed), 3 on bad input. Needs syft and grype on PATH and a current Grype DB.
    """
    try:
        closed_file = load_closed(closed)
        if out is not None:
            check_output_dir(out)
        started = now()
        catalogue = kev.load(started, kev_fetcher)
        outcomes: list[MethodOutcome] = []
        result = run_gate(closed_file, image, catalogue, keep=outcomes)
        if out is not None:
            write_gate_bundle(
                out,
                result=result,
                outcomes=outcomes,
                closed_bytes=closed.read_bytes(),
                started=started,
                finished=now(),
            )
    except (FixproofError, ValueError) as exc:
        typer.echo(f"fixproof: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    if as_json:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        typer.echo(_gate_human(result))
    raise typer.Exit(verdict_exit_code([line.verdict for line in result.results]))


def _gate_kev(line: GateLine) -> str:
    if line.kev.status == "listed" and line.kev.entry is not None:
        return f"in CISA KEV, due {line.kev.entry.due_date}"
    return "not in CISA KEV" if line.kev.status == "not_listed" else "CISA KEV unavailable"


def _read(scanned: dict[str, dict[str, str]]) -> str:
    return "; ".join(
        f"{tool}: image ID {s.get('image_id') or '?'}, manifest {s.get('manifest_digest') or '?'}, "
        f"{s.get('platform', '?')}"
        for tool, s in sorted(scanned.items())
    )


def _gate_human(result: GateResult) -> str:
    if len(result.platforms) == 1 and not result.not_checked:
        lines = [f"image {result.image} ({_read(result.platforms[0].scanned) or 'not read'})"]
    else:
        lines = [f"image {result.image}" + ("" if result.platforms else " (not read)")]
        lines.extend(f"  {p.platform}: {_read(p.scanned)}" for p in result.platforms)
        lines.extend(f"  not checked: {n.platform} ({n.reason})" for n in result.not_checked)
    unavailable = {line.kev.reason for line in result.results if line.kev.status == "unavailable"}
    lines.extend(f"KEV: unavailable ({reason})" for reason in sorted(r for r in unavailable if r))
    pad = " " * 16
    for line in result.results:
        lines.append(
            f"{line.verdict.value:<15} {line.cve}  ({_gate_kev(line)})\n{pad}{line.reason}"
        )
    counts, total = result.summary, len(result.results)
    if counts.still_affected:
        lines.append(
            f"BLOCK: {counts.still_affected} of {total} closed CVEs are back in this image."
        )
    elif counts.unknown:
        lines.append(
            f"CANNOT PROVE: {counts.unknown} of {total} closed CVEs could not be checked; "
            "see the reasons."
        )
    else:
        lines.append(f"PASS: all {total} closed CVEs are proven gone from this image.")
    return "\n".join(lines)


def kev_line(cve: str, status: kev.Kev) -> str:
    """One line on the CVE's CISA KEV status, or why it is not known."""
    if status.status == "unavailable" or status.feed is None:
        return f"KEV: unavailable ({status.reason})"
    feed = f"feed {status.feed.catalog_version}, released {status.feed.date_released}"
    if status.entry is None:
        return f"KEV: {cve} is not in the CISA KEV catalogue ({feed})"
    entry = status.entry
    ransomware = entry.known_ransomware_campaign_use or "not stated"
    return (
        f"KEV: {cve} is in the CISA KEV catalogue: added {entry.date_added}, due "
        f"{entry.due_date}, known ransomware use {ransomware} ({feed})"
    )


def main() -> None:
    """Console entry point: run the app, mapping usage errors to exit code 3."""
    try:
        code = app(standalone_mode=False)
    except typer.Abort:
        sys.exit(EXIT_USAGE)
    except typer.TyperException as exc:  # usage errors (unknown option, missing value, ...)
        show = getattr(exc, "show", None)
        if callable(show):
            show()
        else:
            typer.echo(f"Error: {exc.format_message()}", err=True)
        sys.exit(EXIT_USAGE)
    sys.exit(code if isinstance(code, int) else EXIT_FIXED)


def verdict_exit_code(verdicts: list[Verdict]) -> int:
    if Verdict.STILL_AFFECTED in verdicts:
        return EXIT_AFFECTED
    return EXIT_UNKNOWN if Verdict.UNKNOWN in verdicts else EXIT_FIXED
