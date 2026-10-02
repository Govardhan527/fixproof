"""The `fix.yaml` and `scope.yaml` input formats (ADR-0005 items 1 and 2).

Both are read with `yaml.safe_load` only. Every problem becomes an `InputError` that names the
file, the field and the reason.
"""

from pathlib import Path
from typing import Annotated, Any, Literal, Self

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from fixproof.errors import InputError
from fixproof.model import Contract, CveId, ImageRef, Registry, Text, is_cve_id
from fixproof.purl import NAMESPACE_RULES, build
from fixproof.vers import check_vers

FIX_VERSION = "1.0.0"
SCOPE_VERSION = "1.0.0"

Ecosystem = Literal["deb", "rpm", "apk", "pypi", "npm", "maven"]


class FixPackage(Contract):
    """One package the fix changes, and the versions that carry the fix."""

    ecosystem: Ecosystem
    namespace: Text | None = None
    name: Text
    fixed_version: Text
    fixed_vers: Text | None = Field(
        default=None, description="Extra fixed ranges as a vers string, for backports."
    )

    @model_validator(mode="after")
    def _purl_and_vers_rules(self) -> Self:
        rule = NAMESPACE_RULES[self.ecosystem]
        if rule == "required" and self.namespace is None:
            raise ValueError(f"namespace is required for {self.ecosystem} packages")
        if rule == "prohibited" and self.namespace is not None:
            raise ValueError(f"namespace is not allowed for {self.ecosystem} packages")
        if self.fixed_vers is not None:
            check_vers(self.fixed_vers, self.ecosystem)
        return self

    @property
    def purl(self) -> str:
        """The package's purl without a version, as the VEX names it."""
        return build(self.ecosystem, self.name, namespace=self.namespace)


class FixFile(Contract):
    """`fix.yaml`: the claimed fix for one CVE."""

    schema_version: Literal["1.0.0"]
    cve: CveId
    packages: Annotated[tuple[FixPackage, ...], Field(min_length=1)]

    @field_validator("packages")
    @classmethod
    def _unique_packages(cls, packages: tuple[FixPackage, ...]) -> tuple[FixPackage, ...]:
        purls = [package.purl for package in packages]
        if len(set(purls)) != len(purls):
            raise ValueError("each package may be listed only once")
        return packages


ImageReference = Annotated[
    str, Field(description="registry/repository@sha256:<64 hex>, registry host required")
]


class Cluster(Contract):
    context: Text = Field(description="kubeconfig context name")
    namespaces: Annotated[tuple[Text, ...], Field(min_length=1)]

    @field_validator("namespaces")
    @classmethod
    def _unique_namespaces(cls, namespaces: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(namespaces)) != len(namespaces):
            raise ValueError("each namespace may be listed only once")
        return namespaces


class ScopeFile(Contract):
    """`scope.yaml`: what fixproof may look at, and the registries it may read from."""

    schema_version: Literal["1.0.0"]
    registries: Annotated[tuple[Registry, ...], Field(min_length=1)]
    images: tuple[ImageReference, ...] = ()
    clusters: tuple[Cluster, ...] = ()

    @field_validator("images")
    @classmethod
    def _parse_images(cls, images: tuple[str, ...]) -> tuple[str, ...]:
        refs = [ImageRef.parse(image).reference for image in images]
        if len(set(refs)) != len(refs):
            raise ValueError("each image may be listed only once")
        return images

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.registries)) != len(self.registries):
            raise ValueError("each registry may be listed only once")
        if not self.images and not self.clusters:
            raise ValueError("scope names no images and no clusters")
        contexts = [cluster.context for cluster in self.clusters]
        if len(set(contexts)) != len(contexts):
            raise ValueError("each cluster context may be listed only once")
        for ref in self.image_refs:
            if ref.registry not in self.registries:
                raise ValueError(f"image {ref.reference} is from a registry not in registries")
        return self

    @property
    def image_refs(self) -> tuple[ImageRef, ...]:
        return tuple(ImageRef.parse(image) for image in self.images)


def _problems(error: ValidationError) -> list[str]:
    problems = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "<root>"
        message = item["msg"].removeprefix("Value error, ")
        if item["type"] == "string_type" and isinstance(item["input"], int | float):
            message += " (quote version strings in YAML: 1.10 is read as the number 1.1)"
        problems.append(f"{location}: {message}")
    return problems


def _read_yaml(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(path, [f"cannot read the file: {exc.strerror or exc}"]) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InputError(path, [f"not valid YAML: {exc}"]) from exc


def load_fix(path: Path, cve: str) -> FixFile:
    """Read `fix.yaml` and check it is the fix for `cve`."""
    if not is_cve_id(cve):
        raise InputError(path, [f"--cve {cve!r} is not a CVE id (CVE-YYYY-NNNN...)"])
    try:
        fix = FixFile.model_validate(_read_yaml(path))
    except ValidationError as exc:
        raise InputError(path, _problems(exc)) from exc
    if fix.cve != cve:
        raise InputError(path, [f"cve: the file is for {fix.cve}, not {cve}"])
    return fix


def load_scope(path: Path) -> ScopeFile:
    """Read `scope.yaml`."""
    try:
        return ScopeFile.model_validate(_read_yaml(path))
    except ValidationError as exc:
        raise InputError(path, _problems(exc)) from exc
