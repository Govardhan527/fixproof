"""The HTML summary (ADR-0012 item 6): `report.html` in every bundle.

One self-contained page built from the bundle record, so it shows exactly what the evidence
holds: the counts, the KEV status, the tools and data used, and every asset or workload with its
verdict, reason and digest. Every value is escaped; the page has no JavaScript, and its Content
Security Policy forbids loading anything, so opening it makes no network request. The same
bundle always gives the same page.
"""

import re
from html import escape

from fixproof.bundle import AssetRecord, Bundle
from fixproof.kev import Kev
from fixproof.model import Verdict, WorkloadAsset

CSP = "default-src 'none'; style-src 'unsafe-inline'"
STYLE = """
body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem; color: #1b1f24; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
p.meta { color: #57606a; margin: 0 0 1.25rem; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; padding: .45rem .6rem;
  border-bottom: 1px solid #d0d7de; }
th { background: #f6f8fa; }
code { font-size: .85em; word-break: break-all; }
.counts span { display: inline-block; margin-right: 1rem; font-weight: 600; }
.verdict { font-weight: 600; white-space: nowrap; }
.fixed { color: #1a7f37; } .still_affected { color: #cf222e; } .unknown { color: #9a6700; }
.kev { margin: 1rem 0; padding: .6rem .8rem; background: #f6f8fa; border-left: 4px solid #57606a; }
"""


_EXTERNAL = re.compile(r"""(?:src|href|action)\s*=\s*["']?\s*(?:https?:)?//""", re.IGNORECASE)


def problems(page: str) -> list[str]:
    """What would make a page unsafe to open or not self-contained (checked on every example)."""
    found = []
    if f'content="{CSP}"' not in page:
        found.append("the Content-Security-Policy meta tag is missing")
    if re.search(r"<script", page, re.IGNORECASE):
        found.append("the page has a <script> element")
    if _EXTERNAL.search(page):
        found.append("the page refers to an external resource")
    return found


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _kev(cve: str, kev: Kev) -> str:
    if kev.status == "unavailable" or kev.feed is None:
        return f"CISA KEV: unavailable ({_e(kev.reason)})."
    feed = (
        f"feed {_e(kev.feed.catalog_version)}, released {_e(kev.feed.date_released)}, "
        f"retrieved {_e(kev.feed.retrieved)}"
    )
    if kev.entry is None:
        return f"{_e(cve)} is not in the CISA KEV catalogue ({feed})."
    entry = kev.entry
    return (
        f"<strong>{_e(cve)} is in the CISA KEV catalogue</strong>: added {_e(entry.date_added)}, "
        f"due {_e(entry.due_date)}, known ransomware use "
        f"{_e(entry.known_ransomware_campaign_use or 'not stated')}. Required action: "
        f"{_e(entry.required_action)} ({feed})."
    )


def _tools(bundle: Bundle) -> str:
    parts = []
    for tool in bundle.tools:
        text = f"{tool.get('name')} {tool.get('version')}"
        db = tool.get("db")
        if isinstance(db, dict):
            text += f" (DB {db.get('schemaVersion')}, built {db.get('built')})"
        parts.append(_e(text))
    return ", ".join(parts) or "none recorded"


def _row(record: AssetRecord) -> str:
    asset = record.asset
    image = asset.image.reference if asset.image else "image not resolved"
    if isinstance(asset, WorkloadAsset):
        owner = f"<br>{_e(asset.owner)}" if asset.owner else ""
        what = f"{_e(asset.location)}{owner}"
    else:
        what = "image"
    verdict = record.verdict.value
    return (
        f'<tr><td class="verdict {verdict}">{_e(verdict)}</td><td>{what}</td>'
        f"<td><code>{_e(image)}</code></td><td>{_e(record.reason)}</td></tr>"
    )


def render(bundle: Bundle) -> str:
    """The page for one bundle."""
    counts = bundle.summary
    rows = "\n".join(_row(record) for record in bundle.assets)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fixproof: {_e(bundle.cve)}</title>
<style>{STYLE}</style>
</head>
<body>
<h1>Is {_e(bundle.cve)} gone where it was fixed?</h1>
<p class="meta">fixproof {_e(bundle.fixproof_version)}, run {_e(bundle.started)} to
{_e(bundle.finished)}. Tools: {_tools(bundle)}.</p>
<p class="counts"><span class="fixed">{counts.fixed} {Verdict.FIXED.value}</span>
<span class="still_affected">{counts.still_affected} {Verdict.STILL_AFFECTED.value}</span>
<span class="unknown">{counts.unknown} {Verdict.UNKNOWN.value}</span></p>
<p class="kev">{_kev(bundle.cve, bundle.kev)}</p>
<table>
<thead><tr><th>Verdict</th><th>Workload</th><th>Image</th><th>Reason</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<p class="meta">Evidence: bundle.json, openvex.json, cyclonedx.json and raw/ next to this page,
each listed with its SHA-256 in manifest.json. This is evidence for review, not a
certification.</p>
</body>
</html>
"""
