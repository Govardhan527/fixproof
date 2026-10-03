"""CycloneDX 1.6 VEX (ADR-0012 item 5): the mapping, identities, determinism and validation."""

import hashlib
from pathlib import Path

import pytest
import yaml

from fixproof import cyclonedx
from fixproof.errors import OutputValidationError
from fixproof.inputs import FixFile, ScopeFile
from fixproof.model import Verdict
from fixproof.validation import check_cyclonedx
from fixproof.verify import assess
from fixproof.vex import build_document
from scenario import AUTHOR, FINISH, FIX_YAML, SCOPE_YAML, runner
from test_verify_clusters import SCOPE_YAML as CLUSTER_SCOPE_YAML
from test_verify_clusters import Cluster

FIX = FixFile.model_validate(yaml.safe_load(FIX_YAML))
SCHEMAS = Path(cyclonedx.__file__).parent / "schemas" / "official" / "cyclonedx"
OFFICIAL_SHA256 = {  # CycloneDX specification tag 1.6.2 (SPEC_NOTES §4)
    "bom-1.6.schema.json": "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
    "spdx.schema.json": "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}


def verdicts(scope_yaml: str = SCOPE_YAML) -> list:  # type: ignore[type-arg]
    scope = ScopeFile.model_validate(yaml.safe_load(scope_yaml))
    return [a.verdict for a in assess(FIX, scope, runner(), lambda context: Cluster())]


def test_the_vendored_schemas_are_the_official_files() -> None:
    for name, digest in OFFICIAL_SHA256.items():
        assert hashlib.sha256((SCHEMAS / name).read_bytes()).hexdigest() == digest, name


def test_each_verdict_maps_to_the_spec_state_and_nothing_overclaims() -> None:
    document = cyclonedx.build_bom(FIX, verdicts(), now=FINISH)
    assert document["specVersion"] == "1.6"
    states = {
        v["affects"][0]["ref"].split("@")[0]: (
            v["analysis"]["state"],
            v["analysis"].get("response"),
        )
        for v in document["vulnerabilities"]
    }
    assert states == {
        "pkg:oci/demo-app": ("exploitable", ["update"]),
        "pkg:oci/demo-fixed": ("resolved", None),
        "pkg:oci/demo-broken": ("in_triage", None),
    }
    assert {v["id"] for v in document["vulnerabilities"]} == {FIX.cve}
    assert set(cyclonedx.STATE.values()).isdisjoint({"not_affected", "false_positive"})
    assert set(cyclonedx.STATE) == set(Verdict)


def test_images_have_the_same_purls_as_the_openvex_products() -> None:
    found = verdicts()
    document = cyclonedx.build_bom(FIX, found, now=FINISH)
    vex = build_document(FIX, found, author=AUTHOR, now=FINISH)
    products = {s["products"][0]["@id"] for s in vex["statements"]}
    assert {c["purl"] for c in document["components"]} == products
    assert {c["bom-ref"] for c in document["components"]} == products
    assert all("%2F" in c["purl"] for c in document["components"])  # canonical, not the library's


def test_workloads_sharing_an_image_give_one_entry_per_image() -> None:
    document = cyclonedx.build_bom(FIX, verdicts(CLUSTER_SCOPE_YAML), now=FINISH)
    refs = [v["affects"][0]["ref"] for v in document["vulnerabilities"]]
    assert len(refs) == len(set(refs)) == len(document["components"])


def test_the_same_verdicts_give_the_same_document() -> None:
    found = verdicts()
    first = cyclonedx.build_bom(FIX, found, now=FINISH)
    assert cyclonedx.build_bom(FIX, found, now=FINISH) == first
    assert first["serialNumber"].startswith("urn:uuid:")
    assert first["metadata"]["timestamp"].startswith("2026-10-02T09:01:30")
    other = cyclonedx.build_bom(FIX, found[:2], now=FINISH)
    assert other["serialNumber"] != first["serialNumber"]  # derived from the content


def test_nothing_to_state_and_invalid_documents_are_refused() -> None:
    with pytest.raises(ValueError, match="nothing to state"):
        cyclonedx.build_bom(FIX, [], now=FINISH)
    document = cyclonedx.build_bom(FIX, verdicts(), now=FINISH)
    document["vulnerabilities"][0]["analysis"]["state"] = "fixed"  # not a CycloneDX state
    with pytest.raises(OutputValidationError, match="CycloneDX document"):
        check_cyclonedx(document)
