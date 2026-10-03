"""The HTML summary (ADR-0012 item 6): escaped, self-contained, and true to the bundle."""

from pathlib import Path

import pytest
import yaml

from fixproof import htmlreport, kev
from fixproof.bundle import write_bundle
from fixproof.cyclonedx import build_bom
from fixproof.inputs import FixFile, ScopeFile
from fixproof.verify import assess
from fixproof.vex import build_document
from scenario import AUTHOR, FINISH, FIX_YAML, KEV, KEV_FEED, START, answers
from test_verify_clusters import SCOPE_YAML as CLUSTER_SCOPE_YAML
from test_verify_clusters import Cluster
from tool_outputs import CVE, image_runner

FIX = FixFile.model_validate(yaml.safe_load(FIX_YAML))


def page(tmp_path: Path, kev_status: kev.Kev = KEV) -> str:
    scope = ScopeFile.model_validate(yaml.safe_load(CLUSTER_SCOPE_YAML))
    assessments = assess(FIX, scope, image_runner(answers()), lambda context: Cluster())
    verdicts = [a.verdict for a in assessments]
    bundle = write_bundle(
        tmp_path / "out",
        cve=CVE,
        fix_bytes=FIX_YAML.encode(),
        scope_bytes=CLUSTER_SCOPE_YAML.encode(),
        assessments=assessments,
        vex=build_document(FIX, verdicts, author=AUTHOR, now=FINISH),
        cyclonedx=build_bom(FIX, verdicts, now=FINISH),
        started=START,
        finished=FINISH,
        kev=kev_status,
    )
    written = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert written == htmlreport.render(bundle)  # the page is the bundle, nothing else
    return written


def test_the_page_lists_every_workload_with_its_verdict_digest_and_owner(tmp_path: Path) -> None:
    html = page(tmp_path)
    assert "<title>fixproof: CVE-2023-32681</title>" in html
    assert '<span class="still_affected">3 still_affected</span>' in html
    assert "kind-fixproof/demo/api-7d9-a/app<br>Deployment/api" in html
    assert html.count("<tr><td") == 7  # the image line and six workloads
    assert "image not resolved" in html  # the pending pod
    assert "is not in the CISA KEV catalogue (feed 2026.10.02" in html


def test_the_page_is_self_contained_and_safe_to_open(tmp_path: Path) -> None:
    html = page(tmp_path)
    assert htmlreport.problems(html) == []
    assert htmlreport.CSP == "default-src 'none'; style-src 'unsafe-inline'"


def test_every_value_is_escaped() -> None:
    hostile = kev.Kev(status="unavailable", reason='<script>alert("x")</script>')
    assert "<script>" not in htmlreport._kev(CVE, hostile)
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in htmlreport._kev(CVE, hostile)


def test_a_listed_cve_and_an_unavailable_feed_are_shown(tmp_path: Path) -> None:
    listed = kev.load(START, lambda url: KEV_FEED).status("CVE-2021-44228")
    text = htmlreport._kev("CVE-2021-44228", listed)
    assert "<strong>CVE-2021-44228 is in the CISA KEV catalogue</strong>: added 2021-12-10" in text
    assert "known ransomware use Known" in text
    offline = kev.Kev(status="unavailable", reason="cannot download the KEV feed: offline")
    assert "CISA KEV: unavailable (cannot download the KEV feed: offline)." in page(
        tmp_path, offline
    )


@pytest.mark.parametrize(
    ("bad", "problem"),
    [
        ("<html></html>", "Content-Security-Policy"),
        (f'<meta content="{htmlreport.CSP}"><script>x</script>', "<script>"),
        (f'<meta content="{htmlreport.CSP}"><img src="https://example.com/t.png">', "external"),
        (f'<meta content="{htmlreport.CSP}"><a href="//example.com">x</a>', "external"),
    ],
)
def test_the_page_rules_catch_unsafe_pages(bad: str, problem: str) -> None:
    assert any(problem in found for found in htmlreport.problems(bad))
