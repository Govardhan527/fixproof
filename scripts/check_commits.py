"""Apply the commit message rules to every commit in a push or pull-request range.

    check_commits.py --base <sha> --head <sha>   commits in base..head
    check_commits.py [--head <ref>]              commits on head that are not on origin/main

GitHub sends forty zeros as the push `before` SHA when a push creates a branch. A missing or
all-zero base therefore means: check every commit reachable from head that is not already on the
fallback ref (origin/main). If the fallback ref does not exist, every commit on head is checked.

Exit codes: 0 all commits pass, 1 a commit breaks a rule, 2 git could not resolve the range.
"""

import argparse
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from commit_rules import check_message

ALL_ZEROS = re.compile(r"^0+$")


class GitError(Exception):
    """A git command failed; the message carries git's own stderr."""


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def ref_exists(repo: Path, ref: str) -> bool:
    try:
        git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except GitError:
        return False
    return True


def commits_to_check(repo: Path, base: str | None, head: str, fallback_ref: str) -> list[str]:
    """Return the SHAs to check, oldest first."""
    if base and not ALL_ZEROS.match(base):
        spec = [f"{base}..{head}"]
    elif ref_exists(repo, fallback_ref):
        spec = [head, "--not", fallback_ref]
    else:
        spec = [head]
    return git(repo, "rev-list", "--reverse", *spec, "--").split()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply the commit rules to a range of commits.")
    parser.add_argument("--base", default=None, help="exclusive start of the range")
    parser.add_argument("--head", default="HEAD", help="inclusive end of the range")
    parser.add_argument("--fallback-ref", default="origin/main", help="used when base is unset")
    parser.add_argument("--repo", type=Path, default=Path("."), help="repository to inspect")
    args = parser.parse_args(argv)

    try:
        shas = commits_to_check(args.repo, args.base, args.head, args.fallback_ref)
        messages = {sha: git(args.repo, "log", "-1", "--format=%B", sha) for sha in shas}
    except GitError as exc:
        print(f"check_commits: {exc}", file=sys.stderr)
        return 2

    bad = {sha: errors for sha, message in messages.items() if (errors := check_message(message))}
    for sha, errors in bad.items():
        subject = git(args.repo, "log", "-1", "--format=%s", sha).strip()
        print(f"{sha[:12]} {subject!r}")
        for error in errors:
            print(f"    {error}")
    print(f"checked {len(shas)} commit(s); {len(bad)} broke the commit rules")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
