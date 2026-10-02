import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from fixproof.canonical import iso
from fixproof.errors import OutputValidationError
from fixproof.model import AssetVerdict, ImageAsset, Verdict
from fixproof.vex import STATUS, build_document, image_purl, write_document
from vex_cases import AUTHOR, MIXED, NOW, WEB, example_fix, image, workload

FIX = example_fix("backported-deb")


def document(verdicts: list[AssetVerdict], **overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = {"author": AUTHOR, "now": NOW, **overrides}
    return build_document(FIX, verdicts, **options)


def statuses(doc: dict[str, Any]) -> dict[str, str]:
    return {s["products"][0]["@id"]: s["status"] for s in doc["statements"]}


def test_image_purl_is_canonical() -> None:
    assert image_purl(WEB) == (
        f"pkg:oci/demo-web@{WEB.digest}?repository_url=localhost:5001%2Ffixproof%2Fdemo-web"
    )


def test_verdicts_map_to_statuses_and_never_to_not_affected() -> None:
    assert STATUS == {
        Verdict.FIXED: "fixed",
        Verdict.STILL_AFFECTED: "affected",
        Verdict.UNKNOWN: "under_investigation",
    }
    for verdict in Verdict:
        doc = document([AssetVerdict(asset=ImageAsset(image=WEB), verdict=verdict, reason="r")])
        assert [s["status"] for s in doc["statements"]] == [STATUS[verdict]]
        assert "not_affected" not in json.dumps(doc)
        assert "justification" not in json.dumps(doc)


def test_mixed_run_gives_one_statement_per_image() -> None:
    doc = document(MIXED)
    assert sorted(statuses(doc).values()) == [
        "affected",
        "fixed",
        "fixed",
        "under_investigation",
    ]
    web = next(s for s in doc["statements"] if s["products"][0]["@id"] == image_purl(WEB))
    assert web["status_notes"] == MIXED[0].reason  # two pods, one image, one reason
    subcomponents = web["products"][0]["subcomponents"]
    assert [c["@id"] for c in subcomponents] == [
        "pkg:deb/debian/demo-tools",
        "pkg:deb/debian/libdemo1",
    ]


def test_only_affected_statements_carry_an_action() -> None:
    for statement in document(MIXED)["statements"]:
        if statement["status"] == "affected":
            assert statement["action_statement"] == (
                "Upgrade pkg:deb/debian/libdemo1 to 1.4.2-1 or later, or to a version in "
                "vers:deb/>=1.2.0-3+deb12u1|<1.3; "
                "Upgrade pkg:deb/debian/demo-tools to 1.4.2-1 or later."
            )
        else:
            assert "action_statement" not in statement


def test_distinct_reasons_for_one_image_are_merged() -> None:
    doc = document(
        [
            AssetVerdict(asset=workload("a", WEB), verdict=Verdict.UNKNOWN, reason="b"),
            AssetVerdict(asset=workload("b", WEB), verdict=Verdict.UNKNOWN, reason="a"),
        ]
    )
    assert doc["statements"][0]["status_notes"] == "a; b"


def test_conflicting_verdicts_for_one_image_are_an_error() -> None:
    with pytest.raises(ValueError, match="two verdicts"):
        document(
            [
                AssetVerdict(asset=workload("a", WEB), verdict=Verdict.FIXED, reason="x"),
                AssetVerdict(asset=workload("b", WEB), verdict=Verdict.UNKNOWN, reason="y"),
            ]
        )


def test_workloads_without_an_image_get_no_statement() -> None:
    no_image = AssetVerdict(asset=workload("a", None), verdict=Verdict.UNKNOWN, reason="x")
    assert len(document([MIXED[0], no_image])["statements"]) == 1
    with pytest.raises(ValueError, match="nothing to state"):
        document([no_image])


def test_document_is_deterministic_and_order_independent() -> None:
    assert document(MIXED[::-1]) == document(MIXED)
    assert document(MIXED[3:] + MIXED[:3]) == document(MIXED)
    later = document(MIXED, now=NOW + timedelta(seconds=1))
    assert later["@id"] != document(MIXED)["@id"]


def test_document_id_uses_the_prefix_and_a_content_hash() -> None:
    doc = document(MIXED, id_prefix="https://vex.example.com/docs/")
    assert doc["@id"].startswith("https://vex.example.com/docs/vex-")
    assert len(doc["@id"].rsplit("vex-", 1)[1]) == 32
    assert document(MIXED)["@id"].startswith("https://openvex.dev/docs/fixproof/vex-")


def test_header_fields() -> None:
    doc = document(MIXED, tool_version="9.9.9")
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert (doc["author"], doc["version"], doc["tooling"]) == (AUTHOR, 1, "fixproof 9.9.9")
    assert doc["timestamp"] == "2026-10-02T08:00:00Z"


def test_timestamps_are_utc_whole_seconds() -> None:
    plus_two = timezone(timedelta(hours=2))
    assert iso(datetime(2026, 10, 2, 10, 0, 0, 999_999, tzinfo=plus_two)) == "2026-10-02T08:00:00Z"
    with pytest.raises(ValueError, match="timezone"):
        document(MIXED, now=datetime(2026, 10, 2, 8, 0, 0))
    assert iso(NOW.astimezone(UTC)) == "2026-10-02T08:00:00Z"


def test_author_is_required() -> None:
    with pytest.raises(ValueError, match="author"):
        document(MIXED, author="  ")


def test_an_invalid_document_is_never_returned() -> None:
    with pytest.raises(OutputValidationError, match="is not a 'iri'"):
        document(MIXED, id_prefix="not an iri ")


def test_write_document_validates_and_writes_canonical_json(tmp_path: Path) -> None:
    doc = document(
        [AssetVerdict(asset=ImageAsset(image=image("x/y")), verdict=Verdict.FIXED, reason="r")]
    )
    path = tmp_path / "vex.json"
    write_document(path, doc)
    text = path.read_text(encoding="utf-8")
    assert json.loads(text) == doc
    assert text.endswith("}\n")
    broken = {**doc, "version": 0}
    with pytest.raises(OutputValidationError):
        write_document(tmp_path / "broken.json", broken)
    assert not (tmp_path / "broken.json").exists()
