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

from fixproof import __version__
from fixproof.bundle import check_output_dir, summarise, write_bundle
from fixproof.errors import FixproofError
from fixproof.inputs import load_fix, load_scope
from fixproof.model import AssetVerdict, Verdict, WorkloadAsset
from fixproof.report import verify_summary
from fixproof.verify import assess
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
        assessments = assess(fix_file, scope_file)
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
            started=started,
            finished=finished,
        )
    except (FixproofError, ValueError) as exc:
        typer.echo(f"fixproof: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    summary = summarise(verdicts)
    if as_json:
        report = verify_summary(cve, str(out), verdicts).model_dump(mode="json")
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        for item in verdicts:
            typer.echo(_human(item))
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
    return f"{item.verdict.value:<15} {head}\n{pad}{item.reason}"


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
