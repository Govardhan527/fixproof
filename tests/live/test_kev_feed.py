"""Live check: the real CISA KEV feed, read the way every run reads it (ADR-0012 item 4).

The expected entries have independent sources (SPEC_NOTES §3): CISA added CVE-2023-4911 on
2023-11-21 and CVE-2021-44228 on 2021-12-10; CVE-2023-32681 was not in the feed on 2026-10-03.
Runs weekly in CI (`.github/workflows/live.yml`) and on demand (`make live`).
"""

from datetime import UTC, datetime

import pytest

from fixproof import kev

pytestmark = pytest.mark.live


def test_the_live_feed_validates_and_holds_the_known_entries() -> None:
    catalogue = kev.load(datetime.now(UTC))
    assert isinstance(catalogue, kev.Catalogue), catalogue
    assert catalogue.feed.count == len(catalogue.entries) > 1700
    glibc = catalogue.status("CVE-2023-4911")
    assert glibc.status == "listed"
    assert glibc.entry is not None
    assert (glibc.entry.date_added, glibc.entry.due_date) == ("2023-11-21", "2023-12-12")
    log4shell = catalogue.status("CVE-2021-44228")
    assert log4shell.entry is not None
    assert log4shell.entry.known_ransomware_campaign_use == "Known"
    assert catalogue.status("CVE-2023-32681").status == "not_listed"
