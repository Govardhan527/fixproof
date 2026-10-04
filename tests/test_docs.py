"""The README is held to the CLI and the Makefile (ADR-0013 item 2), both ways."""

import re
from pathlib import Path
from typing import Any

import typer

from fixproof import cli

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def section(heading: str) -> str:
    """The README text from `heading` to the next heading of the same or a higher level."""
    level = heading.split(" ", 1)[0]
    start = README.index(f"\n{heading}\n")
    ends = [README.find(f"\n{h} ", start + 1) for h in ("#" * n for n in range(1, len(level) + 1))]
    return README[start : min([e for e in ends if e != -1] or [len(README)])]


def options_in_table(text: str) -> set[str]:
    return set(re.findall(r"^\| `(--[a-z-]+)` \|", text, re.MULTILINE))


def exits_in_table(text: str) -> set[int]:
    return {int(code) for code in re.findall(r"^\| `([0-9])` \|", text, re.MULTILINE)}


def commands() -> dict[str, Any]:
    """The CLI's commands (typer 0.27 bundles its own Click, so no click import)."""
    group: Any = typer.main.get_command(cli.app)
    found: dict[str, Any] = group.commands
    return found


def cli_options(name: str) -> set[str]:
    return {
        option
        for param in commands()[name].params
        if param.param_type_name == "option"
        for option in param.opts
        if option.startswith("--") and option != "--help"
    }


def test_the_verify_options_table_is_the_cli() -> None:
    assert options_in_table(section("### Step 3. Run")) == cli_options("verify")


def test_the_gate_options_table_is_the_cli() -> None:
    gate = section("### The release gate: never ship a closed CVE again")
    assert options_in_table(gate) == cli_options("gate")
    assert exits_in_table(gate) == {
        cli.EXIT_FIXED,
        cli.EXIT_AFFECTED,
        cli.EXIT_UNKNOWN,
        cli.EXIT_USAGE,
    }


def test_the_exit_code_table_is_the_cli() -> None:
    assert exits_in_table(section("### Exit codes")) == {
        cli.EXIT_FIXED,
        cli.EXIT_AFFECTED,
        cli.EXIT_UNKNOWN,
        cli.EXIT_USAGE,
    }


def test_every_command_the_readme_runs_exists() -> None:
    used = set(re.findall(r"^\$ fixproof ([a-z]+)", README, re.MULTILINE))
    assert used <= set(commands())
    assert {"verify", "gate"} <= used


def test_every_make_target_the_readme_names_exists() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    phony = set(re.search(r"^\.PHONY: (.+)$", makefile, re.MULTILINE).group(1).split())  # type: ignore[union-attr]
    named = set(re.findall(r"`make ([a-z-]+)`|^\$ make ([a-z-]+)", README, re.MULTILINE))
    targets = {a or b for a, b in named}
    assert targets <= phony, targets - phony
    assert {"demo", "check"} <= targets
