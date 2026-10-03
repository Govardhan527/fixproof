import hashlib
import json
from pathlib import Path

import pytest
import yaml

from fixproof.bundle import OutputExistsError, write_bundle
from fixproof.errors import OutputValidationError
from fixproof.inputs import FixFile, ScopeFile
from fixproof.model import Verdict
from fixproof.validation import build_validator, load_schema, schema_errors
from fixproof.verify import assess
from fixproof.vex import build_document
from scenario import AUTHOR, FINISH, FIX_YAML, KEV, SCOPE_YAML, START, runner
from tool_outputs import CVE, MARKER

FIX = FixFile.model_validate(yaml.safe_load(FIX_YAML))
SCOPE = ScopeFile.model_validate(yaml.safe_load(SCOPE_YAML))


def write(out: Path) -> None:
    assessments = assess(FIX, SCOPE, runner())
    vex = build_document(FIX, [a.verdict for a in assessments], author=AUTHOR, now=FINISH)
    write_bundle(
        out,
        cve=CVE,
        fix_bytes=FIX_YAML.encode(),
        scope_bytes=SCOPE_YAML.encode(),
        assessments=assessments,
        vex=vex,
        started=START,
        finished=FINISH,
        kev=KEV,
    )


def test_the_scenario_gives_one_of_each_verdict() -> None:
    verdicts = [a.verdict.verdict for a in assess(FIX, SCOPE, runner())]
    assert verdicts == [Verdict.STILL_AFFECTED, Verdict.FIXED, Verdict.UNKNOWN]


def test_bundle_layout_and_manifest(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    write(out)
    files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert files == [
        "bundle.json",
        "manifest.json",
        "openvex.json",
        "raw/001-grype.json",
        "raw/001-sbom_version.json",
        "raw/002-grype.json",
        "raw/002-sbom_version.json",
        "raw/003-sbom_version.json",  # grype failed on image 3, so it has no output to keep
    ]
    manifest = json.loads((out / "manifest.json").read_text())
    assert [entry["path"] for entry in manifest["files"]] == [
        f for f in files if f != "manifest.json"
    ]
    for entry in manifest["files"]:
        data = (out / entry["path"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        assert entry["size"] == len(data)


def test_bundle_record(tmp_path: Path) -> None:
    write(tmp_path)
    bundle = json.loads((tmp_path / "bundle.json").read_text())
    assert bundle["summary"] == {"fixed": 1, "still_affected": 1, "unknown": 1}
    assert (bundle["started"], bundle["finished"]) == (
        "2026-10-02T09:00:00Z",
        "2026-10-02T09:01:30Z",
    )
    assert bundle["inputs"]["fix_sha256"] == hashlib.sha256(FIX_YAML.encode()).hexdigest()
    first = bundle["assets"][0]
    assert [r["raw_ref"] for r in first["results"]] == [
        "raw/001-grype.json",
        "raw/001-sbom_version.json",
    ]
    assert first["asset"]["kind"] == "image"
    assert first["scanned"]["grype"]["platform"] == "linux/amd64"
    third = bundle["assets"][2]
    assert third["results"][0]["raw_ref"] is None
    assert "grype exited 1: ERROR failed to fetch image" in third["reason"]
    tools = {tool["name"]: tool for tool in bundle["tools"]}
    assert tools["grype"]["db"]["schemaVersion"] == "v6.1.9"
    assert tools["syft"]["schema"] == "16.1.11"


def test_bundle_and_manifest_match_their_schemas(tmp_path: Path) -> None:
    write(tmp_path)
    for name in ("bundle", "manifest"):
        validator = build_validator(load_schema(f"{name}.schema.json"))
        assert schema_errors(validator, json.loads((tmp_path / f"{name}.json").read_text())) == []


def test_no_image_config_or_file_contents_reach_the_bundle(tmp_path: Path) -> None:
    write(tmp_path)
    for path in tmp_path.rglob("*.json"):
        text = path.read_text()
        assert MARKER not in text, path
        assert "bWFya2Vy" not in text, path


def test_existing_evidence_is_never_overwritten(tmp_path: Path) -> None:
    write(tmp_path / "run")
    with pytest.raises(OutputExistsError, match="already exists and is not empty"):
        write(tmp_path / "run")
    (tmp_path / "a-file").write_text("x")
    with pytest.raises(OutputExistsError):
        write(tmp_path / "a-file")


def test_an_empty_directory_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    write(tmp_path / "empty")
    assert (tmp_path / "empty" / "manifest.json").is_file()


def test_an_invalid_vex_writes_nothing(tmp_path: Path) -> None:
    with pytest.raises(OutputValidationError):
        write_bundle(
            tmp_path / "out",
            cve=CVE,
            fix_bytes=b"",
            scope_bytes=b"",
            assessments=[],
            vex={"not": "openvex"},
            started=START,
            finished=FINISH,
            kev=KEV,
        )
    assert not (tmp_path / "out").exists()
