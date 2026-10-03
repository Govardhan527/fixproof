"""Write the project's JSON Schemas from the pydantic contracts (ADR-0003).

generate_schemas.py           rewrite src/fixproof/schemas/<format>.schema.json
generate_schemas.py --check   exit 1 if a committed schema differs from its model

The schemas describe structure. Rules that span fields (namespace rules per ecosystem, vers
syntax, registries allowlist) are enforced by the loaders in fixproof.inputs.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from fixproof.bundle import BUNDLE_VERSION, MANIFEST_VERSION, Bundle, Manifest
from fixproof.gate import GATE_VERSION, GateResult
from fixproof.inputs import (
    CLOSED_VERSION,
    FIX_VERSION,
    SCOPE_VERSION,
    ClosedFile,
    FixFile,
    ScopeFile,
)
from fixproof.report import SUMMARY_VERSION, VerifySummary

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src" / "fixproof" / "schemas"
ID_BASE = "https://github.com/Govardhan527/fixproof/schemas"
FORMATS: dict[str, tuple[type[BaseModel], str]] = {
    "bundle": (Bundle, BUNDLE_VERSION),
    "closed": (ClosedFile, CLOSED_VERSION),
    "gate-result": (GateResult, GATE_VERSION),
    "fix": (FixFile, FIX_VERSION),
    "manifest": (Manifest, MANIFEST_VERSION),
    "scope": (ScopeFile, SCOPE_VERSION),
    "verify-summary": (VerifySummary, SUMMARY_VERSION),
}


def render(name: str, model: type[BaseModel], version: str) -> str:
    schema: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{ID_BASE}/{name}/{version}",
        **model.model_json_schema(),
    }
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate JSON Schemas from the contracts.")
    parser.add_argument("--check", action="store_true", help="fail if committed schemas differ")
    args = parser.parse_args(argv)

    stale = []
    for name, (model, version) in FORMATS.items():
        path = OUTPUT / f"{name}.schema.json"
        text = render(name, model, version)
        if path.is_file() and path.read_text(encoding="utf-8") == text:
            continue
        stale.append(path)
        if not args.check:
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if args.check:
        for path in stale:
            print(f"{path.relative_to(ROOT)} is out of date; run {Path(__file__).name}")
        return 1 if stale else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
