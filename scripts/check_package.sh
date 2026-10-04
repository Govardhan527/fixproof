#!/usr/bin/env bash
# Build the wheel and sdist, install the wheel into a fresh environment, and check it works as
# a user would get it (ADR-0013 item 4): the command runs, the version is the project's, and the
# packaged schemas (the official ones included) validate the example documents. `twine check`
# fails on metadata PyPI would reject or a README it cannot render (ADR-0013 Amendment 2).
#   scripts/check_package.sh WORKDIR
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="${1:?usage: check_package.sh WORKDIR}"
rm -rf "$work" && mkdir -p "$work"
work="$(cd "$work" && pwd)"  # absolute: the checks below run from another directory
uv build --no-sources --out-dir "$work/dist" "$repo"
uvx --from twine==7.0.0 twine check --strict "$work"/dist/*
uv venv --quiet --python 3.12 "$work/venv"
uv pip install --quiet --python "$work/venv/bin/python" "$work"/dist/*.whl
expected="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo/pyproject.toml")"
actual="$("$work/venv/bin/fixproof" --version)"
[[ "$actual" == "fixproof $expected" ]] || { echo "version: $actual, expected $expected" >&2; exit 1; }
cd "$work"  # not the repository: the installed package, not the source tree, is checked
"$work/venv/bin/python" - "$repo/examples" <<'PY'
import json, sys
from pathlib import Path
import fixproof
from fixproof.validation import cyclonedx_errors, openvex_errors

examples = Path(sys.argv[1])
assert "site-packages" in fixproof.__file__, fixproof.__file__
for path in sorted((examples / "openvex").glob("*.json")):
    assert openvex_errors(json.loads(path.read_text())) == [], path
for path in sorted((examples / "cyclonedx").glob("*.json")):
    assert cyclonedx_errors(json.loads(path.read_text())) == [], path
print("the installed wheel validates the examples with its packaged schemas")
PY
ls -l "$work/dist"
