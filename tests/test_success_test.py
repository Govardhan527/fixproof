"""The SUCCESS TEST checks `make demo` applies (scripts/success_test.py): they pass the real
shape and catch each way a result could fall short."""

import json
from pathlib import Path
from typing import Any

import success_test

DIGEST = "@sha256:" + "ab" * 32
VEX = json.loads((Path(__file__).parents[1] / "examples" / "openvex" / "mixed.json").read_text())


def item(verdict: str, pod: str, reason: str = "because") -> dict[str, Any]:
    return {
        "verdict": verdict,
        "workload": f"kind-fixproof/fixproof-demo/{pod}-5d6f7d95c8-qt77n/app",
        "asset": f"localhost:5001/fixproof/{pod}{DIGEST}" if verdict != "unknown" else None,
        "reason": reason,
    }


def good() -> dict[str, Any]:
    return {
        "summary": {"fixed": 2, "still_affected": 3, "unknown": 1},
        "assets": [
            item("still_affected", "orders"),
            item("still_affected", "billing"),
            item("still_affected", "reports"),
            item("fixed", "payments"),
            item("fixed", "search"),
            item("unknown", "partner-gateway", "both methods failed"),
        ],
    }


def test_the_real_shape_passes_every_step() -> None:
    assert success_test.check_step1(1, good()) == []
    assert success_test.check_step2(VEX) == []
    assert success_test.check_step3(1, 0) == []


def test_step1_catches_wrong_counts_codes_digests_and_reasons() -> None:
    wrong = good()
    wrong["summary"] = {"fixed": 3, "still_affected": 3, "unknown": 0}
    assert "summary is" in success_test.check_step1(1, wrong)[0]
    assert "exit code 2" in success_test.check_step1(2, good())[0]
    no_digest = good()
    no_digest["assets"][0]["asset"] = None
    assert success_test.check_step1(1, no_digest) == [
        "kind-fixproof/fixproof-demo/orders-5d6f7d95c8-qt77n/app: no image digest"
    ]
    no_reason = good()
    no_reason["assets"][5]["reason"] = ""
    assert "unknown without a reason" in success_test.check_step1(1, no_reason)[0]
    stray = good()
    stray["assets"][1]["workload"] = None
    assert "not a demo workload" in success_test.check_step1(1, stray)[0]


def test_step2_catches_invalid_vex_and_not_affected() -> None:
    bad = dict(VEX, statements=[dict(VEX["statements"][0], status="not_affected")])
    problems = success_test.check_step2(bad)
    assert "a not_affected statement was written" in problems
    assert any(p.startswith("OpenVEX schema:") for p in problems)


def test_step3_needs_non_zero_on_the_reintroduced_image_and_zero_on_the_clean_one() -> None:
    assert success_test.check_step3(0, 0) == [
        "gate exited 0 on an image that brings the closed CVE back"
    ]
    assert success_test.check_step3(2, 2) == [
        "gate exited 2 on an image without the CVE, expected 0"
    ]
