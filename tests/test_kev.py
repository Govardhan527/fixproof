"""KEV enrichment (ADR-0012 item 4): a real-feed excerpt, every failure path, no network."""

import hashlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fixproof import kev
from fixproof.validation import load_schema

NOW = datetime(2026, 10, 3, 9, 0, 0, tzinfo=UTC)
# Two real entries from the CISA feed of 2026-10-02 (SPEC_NOTES §3), in the feed's own layout
EXCERPT = (Path(__file__).parent / "fixtures" / "kev" / "excerpt.json").read_bytes()
KEV_SCHEMA_SHA256 = "0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7"


def serve(data: bytes) -> kev.Fetcher:
    return lambda url: data


def test_the_vendored_schema_is_the_official_file() -> None:
    data = json.dumps(load_schema(kev.KEV_SCHEMA))  # parses
    assert data
    raw = (Path(kev.__file__).parent / "schemas" / kev.KEV_SCHEMA).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == KEV_SCHEMA_SHA256


def test_a_listed_cve_carries_its_kev_fields_and_the_feed_record() -> None:
    catalogue = kev.load(NOW, serve(EXCERPT))
    status = catalogue.status("CVE-2021-44228")
    assert status.status == "listed"
    assert status.entry is not None
    assert (status.entry.date_added, status.entry.due_date) == ("2021-12-10", "2021-12-24")
    assert status.entry.known_ransomware_campaign_use == "Known"
    assert status.feed == kev.KevFeed(
        url=kev.KEV_URL,
        catalog_version="2026.10.02",
        date_released="2026-10-02T15:19:38.2945Z",
        retrieved="2026-10-03T09:00:00Z",
        sha256=hashlib.sha256(EXCERPT).hexdigest(),
        count=2,
    )


def test_a_cve_not_in_the_feed_is_not_listed() -> None:
    status = kev.load(NOW, serve(EXCERPT)).status("CVE-2023-32681")
    assert (status.status, status.entry, status.reason) == ("not_listed", None, None)
    assert status.feed is not None


def failing(url: str) -> bytes:
    raise kev.KevFetchError("cannot download the KEV feed: no route to host")


@pytest.mark.parametrize(
    ("fetcher", "reason"),
    [
        (failing, "cannot download the KEV feed: no route to host"),
        (serve(b"<html>maintenance</html>"), "the KEV feed is not JSON"),
        (serve(b'{"catalogVersion": "x"}'), "the KEV feed does not match its schema"),
    ],
)
def test_an_unusable_feed_is_unavailable_with_the_reason(fetcher: Any, reason: str) -> None:
    status = kev.load(NOW, fetcher).status("CVE-2021-44228")
    assert status.status == "unavailable"
    assert (status.feed, status.entry) == (None, None)
    assert status.reason is not None
    assert reason in status.reason


class FakeResponse(io.BytesIO):
    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def test_fetch_reads_https_within_the_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    def urlopen(request: Any, timeout: float) -> FakeResponse:
        seen.append((request.full_url, timeout))
        return FakeResponse(EXCERPT)

    monkeypatch.setattr(kev.urllib.request, "urlopen", urlopen)
    assert kev.fetch(kev.KEV_URL) == EXCERPT
    assert seen == [(kev.KEV_URL, kev.TIMEOUT_SECONDS)]


def test_fetch_refuses_plain_http_oversized_feeds_and_network_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(kev.KevFetchError, match="non-HTTPS"):
        kev.fetch("http://www.cisa.gov/feed.json")
    monkeypatch.setattr(kev, "MAX_BYTES", 10)
    monkeypatch.setattr(kev.urllib.request, "urlopen", lambda r, timeout: FakeResponse(EXCERPT))
    with pytest.raises(kev.KevFetchError, match="larger than 10 bytes"):
        kev.fetch(kev.KEV_URL)

    def down(request: Any, timeout: float) -> FakeResponse:
        raise kev.urllib.error.URLError("temporary failure in name resolution")

    monkeypatch.setattr(kev.urllib.request, "urlopen", down)
    with pytest.raises(kev.KevFetchError, match="name resolution"):
        kev.fetch(kev.KEV_URL)
