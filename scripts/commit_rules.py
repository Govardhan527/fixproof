"""Commit message rules shared by the commit-msg hook and scripts/check_commits.py.

The policy is ADR-0004: commits carry the owner's identity only, so any co-author trailer, any
tool-generated footer and the robot emoji are rejected, and subjects follow Conventional Commits
with a milestone scope. Keep one copy here so the local hook and the CI check can never drift.
"""

import re

FORBIDDEN: tuple[str, ...] = (
    r"(?im)^co-authored-by:",
    r"(?im)^\W*generated (with|by)\b",
    "\U0001f916",
)
SUBJECT = r"^(feat|fix|test|docs|refactor|perf|build|ci|chore)\((M\d+|infra)\): \S.{0,70}$"
SUBJECT_HELP = "subject must look like 'feat(M2): short summary' (max ~72 chars)"

# `git commit --verbose` appends the diff below this line. It is not part of the message.
SCISSORS = "# ------------------------ >8 ------------------------"


def check_message(message: str) -> list[str]:
    """Return every rule the commit message breaks. An empty list means it is acceptable."""
    message = message.split(SCISSORS, 1)[0]
    lines = [line for line in message.splitlines() if not line.startswith("#")]
    errors = [f"forbidden attribution matched: {p}" for p in FORBIDDEN if re.search(p, message)]
    if not lines or not re.match(SUBJECT, lines[0]):
        errors.append(SUBJECT_HELP)
    return errors
