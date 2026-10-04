"""Running the external tools (Syft, Grype) without a shell.

The tools inherit the environment, so registry credentials reach them the standard way (Docker
config or environment variables); fixproof never reads, logs or stores them. Error text kept
from a tool's stderr is cut to one line, and any `user:password@` in a URL is masked.
"""

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, cast

TIMEOUT_SECONDS = 1800
MAX_OUTPUT_BYTES = 512 * 1024 * 1024  # ADR-0013; real outputs were 0.3 to 1.8 MB (SPEC_NOTES §12)
STDERR_TAIL_BYTES = 64 * 1024
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


def _drain(stream: IO[bytes], limit: int, sink: bytearray, over: threading.Event) -> None:
    """Copy `stream` into `sink` until it ends or passes `limit` bytes (then set `over`)."""
    while chunk := stream.read(1 << 20):
        if len(sink) + len(chunk) > limit:
            over.set()
            return
        sink.extend(chunk)


def run_tool(
    name: str,
    args: Sequence[str],
    env: Mapping[str, str],
    timeout: float = TIMEOUT_SECONDS,
    max_output: int = MAX_OUTPUT_BYTES,
) -> ToolRun:
    """Run `name` from PATH with `args`, adding `env` to the inherited environment.

    Standard output is read as it comes, up to `max_output` bytes: beyond that the tool is
    stopped and the run is a problem (ADR-0013 item 3), so a huge or runaway output can neither
    exhaust memory nor pass for a result. Only the last part of standard error is kept.
    """
    path = shutil.which(name)
    if path is None:
        return ToolRun(None, b"", "", f"{name} not found on PATH")
    with tempfile.TemporaryFile() as errors:
        try:
            # No shell: a PATH-resolved binary and a list of arguments fixproof built itself.
            process = subprocess.Popen(  # noqa: S603
                [path, *args], stdout=subprocess.PIPE, stderr=errors, env={**os.environ, **env}
            )
        except OSError as exc:
            return ToolRun(None, b"", "", f"{name} could not start: {exc.strerror or exc}")
        stdout = cast(IO[bytes], process.stdout)
        output, over = bytearray(), threading.Event()
        reader = threading.Thread(target=_drain, args=(stdout, max_output, output, over))
        reader.start()
        deadline = time.monotonic() + timeout
        timed_out = False
        while process.poll() is None and not over.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                process.wait(timeout=min(0.2, remaining))
            except subprocess.TimeoutExpired:
                continue
        if timed_out or over.is_set():
            process.kill()
        process.wait()
        reader.join()
        stdout.close()
        if timed_out:
            return ToolRun(None, b"", "", f"{name} timed out after {timeout:g} seconds")
        if over.is_set():
            return ToolRun(None, b"", "", f"{name} wrote more than {max_output} bytes of output")
        size = errors.seek(0, os.SEEK_END)
        errors.seek(max(0, size - STDERR_TAIL_BYTES))
        stderr = errors.read().decode("utf-8", errors="replace")
    return ToolRun(process.returncode, bytes(output), stderr)


def last_line(text: str, limit: int = 200) -> str:
    """The last non-empty line of tool output, without colour codes or URL credentials."""
    lines = [line.strip() for line in _ANSI.sub("", text).splitlines() if line.strip()]
    line = _USERINFO.sub("://***@", lines[-1]) if lines else "no error output"
    return line if len(line) <= limit else line[: limit - 3] + "..."
