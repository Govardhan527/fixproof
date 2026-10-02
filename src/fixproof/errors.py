"""Typed errors. Every message says what is wrong and where, so the user can act on it."""

from pathlib import Path


class FixproofError(Exception):
    """Base class for every error fixproof raises on purpose."""


class InputError(FixproofError):
    """An input file (`fix.yaml`, `scope.yaml`) is missing, unreadable or invalid."""

    def __init__(self, path: Path, problems: list[str]) -> None:
        self.path = path
        self.problems = problems
        super().__init__(f"{path}: invalid input\n  " + "\n  ".join(problems))


class OutputValidationError(FixproofError):
    """A document fixproof built fails its schema, so it is not written."""

    def __init__(self, document: str, problems: list[str]) -> None:
        self.document = document
        self.problems = problems
        super().__init__(f"{document} fails its schema:\n  " + "\n  ".join(problems))
