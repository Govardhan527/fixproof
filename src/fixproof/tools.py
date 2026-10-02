"""Running the external tools (Syft, Grype) without a shell.

The tools inherit the environment, so registry credentials reach them the standard way (Docker
config or environment variables); fixproof never reads, logs or stores them. Error text kept
from a tool's stderr is cut to one line, and any `user:password@` in a URL is masked.
"""

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

TIMEOUT_SECONDS = 1800
_USERINFO = re.compile(r"://[^/@\s]+@")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@dataclass(frozen=True)
class ToolRun:
    """What one tool invocation produced. `problem` is set when it did not run to completion."""

    exit_code: int | None
    stdout: bytes
    stderr: str
    problem: str | None = None


Runner = Callable[[str, Sequence[str], Mapping[str, str]], ToolRun]


def run_tool(
    name: str, args: Sequence[str], env: Mapping[str, str], timeout: float = TIMEOUT_SECONDS
) -> ToolRun:
    """Run `name` from PATH with `args`, adding `env` to the inherited environment."""
    path = shutil.which(name)
    if path is None:
        return ToolRun(None, b"", "", f"{name} not found on PATH")
    try:
        # No shell: a PATH-resolved binary and a list of arguments fixproof built itself.
        done = subprocess.run(  # noqa: S603
            [path, *args],
            capture_output=True,
            env={**os.environ, **env},
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(None, b"", "", f"{name} timed out after {timeout:g} seconds")
    except OSError as exc:
        return ToolRun(None, b"", "", f"{name} could not start: {exc.strerror or exc}")
    return ToolRun(done.returncode, done.stdout, done.stderr.decode("utf-8", errors="replace"))


def last_line(text: str, limit: int = 200) -> str:
    """The last non-empty line of tool output, without colour codes or URL credentials."""
    lines = [line.strip() for line in _ANSI.sub("", text).splitlines() if line.strip()]
    line = _USERINFO.sub("://***@", lines[-1]) if lines else "no error output"
    return line if len(line) <= limit else line[: limit - 3] + "..."
