"""Canonical JSON: the one byte form used for every file fixproof writes and hashes."""

import json
from datetime import UTC, datetime
from typing import Any


def to_json(data: Any) -> bytes:
    """Sorted keys, two-space indent, UTF-8, trailing newline."""
    return (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def iso(value: datetime) -> str:
    """A UTC RFC 3339 timestamp with whole seconds and a `Z`, e.g. 2026-10-02T08:00:00Z."""
    if value.tzinfo is None:
        raise ValueError("timestamps must carry a timezone; inject an aware clock")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
