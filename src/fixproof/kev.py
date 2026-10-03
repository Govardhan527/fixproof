"""CISA KEV enrichment (ADR-0012 item 4; SPEC_NOTES §3).

The feed is fetched once per run over HTTPS, checked against its official schema (vendored byte
for byte), and recorded with its version, release time, retrieval time and SHA-256. Whether a CVE
is in KEV is information for the reader; it never changes a verdict or an exit code. If the feed
cannot be fetched or is not valid, the run records `unavailable` and the reason.
"""

import hashlib
import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import Field

from fixproof.canonical import iso
from fixproof.model import Contract, CveId, Text
from fixproof.validation import build_validator, load_schema, schema_errors

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_SCHEMA = "official/kev.schema.json"
TIMEOUT_SECONDS = 30
MAX_BYTES = 16 * 1024 * 1024  # the feed was 1.77 MB on 2026-10-03

Fetcher = Callable[[str], bytes]


class KevFeed(Contract):
    """The feed a run used."""

    url: Text
    catalog_version: Text
    date_released: Text
    retrieved: Text
    sha256: Text = Field(pattern=r"^[a-f0-9]{64}$")
    count: int = Field(ge=0)


class KevEntry(Contract):
    """The KEV fields fixproof reports for a listed CVE."""

    cve: CveId
    vendor_project: Text
    product: Text
    vulnerability_name: Text
    date_added: Text
    due_date: Text
    required_action: Text
    known_ransomware_campaign_use: Text | None = None


class Kev(Contract):
    """One CVE's KEV status in a run: `listed`, `not_listed`, or `unavailable` with the reason."""

    status: Literal["listed", "not_listed", "unavailable"]
    feed: KevFeed | None = None
    entry: KevEntry | None = None
    reason: Text | None = None


@dataclass(frozen=True)
class Catalogue:
    feed: KevFeed
    entries: dict[str, KevEntry]

    def status(self, cve: str) -> Kev:
        entry = self.entries.get(cve)
        if entry is None:
            return Kev(status="not_listed", feed=self.feed)
        return Kev(status="listed", feed=self.feed, entry=entry)


@dataclass(frozen=True)
class Unavailable:
    reason: str

    def status(self, cve: str) -> Kev:
        return Kev(status="unavailable", reason=self.reason)


class KevFetchError(Exception):
    """The feed could not be downloaded."""


def fetch(url: str) -> bytes:
    """Download `url` over HTTPS, refusing anything larger than MAX_BYTES."""
    if not url.startswith("https://"):
        raise KevFetchError(f"refusing a non-HTTPS KEV URL: {url}")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            data: bytes = response.read(MAX_BYTES + 1)
    except (OSError, ValueError) as exc:  # URLError and HTTPError are OSErrors
        raise KevFetchError(f"cannot download the KEV feed: {exc}") from exc
    if len(data) > MAX_BYTES:
        raise KevFetchError(f"the KEV feed is larger than {MAX_BYTES} bytes")
    return data


def load(now: datetime, fetcher: Fetcher = fetch, url: str = KEV_URL) -> Catalogue | Unavailable:
    """Fetch and check the feed once; never raises."""
    try:
        data = fetcher(url)
    except KevFetchError as exc:
        return Unavailable(str(exc))
    try:
        feed = json.loads(data)
    except ValueError as exc:
        return Unavailable(f"the KEV feed is not JSON: {exc}")
    problems = schema_errors(build_validator(load_schema(KEV_SCHEMA)), feed)
    if problems:
        shown = "; ".join(problems[:3])
        return Unavailable(f"the KEV feed does not match its schema ({len(problems)}): {shown}")
    entries = {
        item["cveID"]: KevEntry(
            cve=item["cveID"],
            vendor_project=item["vendorProject"],
            product=item["product"],
            vulnerability_name=item["vulnerabilityName"],
            date_added=item["dateAdded"],
            due_date=item["dueDate"],
            required_action=item["requiredAction"],
            known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse"),
        )
        for item in feed["vulnerabilities"]
    }
    record = KevFeed(
        url=url,
        catalog_version=feed["catalogVersion"],
        date_released=feed["dateReleased"],
        retrieved=iso(now),
        sha256=hashlib.sha256(data).hexdigest(),
        count=feed["count"],
    )
    return Catalogue(record, entries)
