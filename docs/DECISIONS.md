# Decisions

Numbered ADRs: context, options, decision, consequence. Every dependency choice and every
interface change gets one. Status is `Proposed` until the owner approves, then `Accepted`.

## ADR-0001: Licence

- **Date:** 2026-10-02. **Status:** Accepted (the owner committed the licence).
- **Context:** M0 needs a licence.
- **Options:** Apache-2.0, for its express patent grant; MIT, which acvp-assay uses.
- **Decision:** Apache-2.0. The owner committed the Apache License 2.0 text as `LICENSE` in
  `ad1835e Initial commit` (2026-10-02). `pyproject.toml` declares `license = "Apache-2.0"`.
- **Consequence:** Contributions carry an express patent grant. Third-party code added later must
  be Apache-2.0 compatible. Two GPL sources named in the plan are affected: `python-debian` is
  GPL-2.0-or-later (OQ-4) and apk-tools `src/version.c` is GPL-2.0-only (SPEC_NOTES §8), so the
  apk comparator is written from its documented behaviour and tests, never copied.

## ADR-0002: Stack

- **Date:** 2026-10-02. **Status:** Accepted (owner approved 2026-10-02, including the (A) items).
- **Context:** The stack was planned up front. This ADR confirms it, pins the versions the
  milestones depend on, and lists where this project differs from the plan.
- **Core stack, as planned:** Python 3.12 (`.python-version`, `requires-python >=3.12`), uv,
  typer, pydantic v2, Syft and Grype as pinned external binaries invoked with JSON output (their
  versions recorded in every evidence bundle), the `kubernetes` Python client with a read-only
  ServiceAccount (get and list on pods and replicasets only), `packaging` (PyPI versions),
  `packageurl-python` (purls), jsonschema (OpenVEX and output schema validation),
  `cyclonedx-python-lib` (CycloneDX VEX, M5), kind (integration tests), ruff, mypy --strict,
  pytest, pytest-cov, pytest-socket, pip-audit, gitleaks.
- **Further choices:**
  1. (A) **OpenVEX v0.2.0.** The specification is pinned at tag `v0.2.0`. That tag holds no JSON
     Schema; the schema `openvex_json_schema.json` (`$id`
     `https://github.com/openvex/spec/openvex_json_schema_0.2.0.json`) is pinned at commit
     `a68ccd19b15a9604d28ef66ebf33f27a772ba4ec` (2025-03-31, the last change to that file),
     SHA-256 `9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238`. It is vendored
     in M1. `@context` is `https://openvex.dev/ns/v0.2.0` (OQ-1, answered). See SPEC_NOTES §1.
  2. (A) **CycloneDX 1.6, patch 1.6.2** (2026-06-02) for the M5 VEX output, as planned. 1.7.2 is
     the latest release (OQ-3). See SPEC_NOTES §4.
  3. (A) **Build backend `uv_build`** (`>=0.12.9,<0.13`): uv's own backend, no extra tool.
     Alternative: hatchling.
  4. (A) **Dev dependency `types-jsonschema`**: typeshed stubs so `mypy --strict` covers code that
     calls jsonschema. Alternative: `ignore_missing_imports`, which turns those calls into `Any`.
  5. **Add runtime dependencies late:** each is added, with its own ADR entry, in the milestone
     that first imports it (typer, pydantic, jsonschema and a YAML parser in M1; `packaging` and
     `packageurl-python` in M2 or M3; `kubernetes` in M4; `cyclonedx-python-lib` and a template
     engine for the HTML summary in M5). M0 ships with none. `jsonschema` is a dev dependency
     until then, used by `scripts/validate_outputs.py`.
  6. **Version comparators (M3), proposed:** PyPI via `packaging`; dpkg, rpm, apk and Maven
     written in this project from the primary specifications with spec-derived test tables
     (dpkg pending OQ-4); npm per SemVer 2.0.0 precedence and node-semver range rules, library
     or in-house decided in the M3 ADR. Ecosystems: deb, rpm, apk, pypi, npm, maven, the six
     named for M3.
  7. **External binaries (pinned by version and SHA-256 when first installed):** Syft v1.54.0
     (2026-10-01), Grype v0.119.0 (2026-09-17), kind v0.33.0 (2026-08-26, default node image
     `kindest/node:v1.37.0`). These are the latest releases on 2026-10-02 and are re-checked when
     M2 and M4 install them. See SPEC_NOTES §12.
  8. **CI installs with `uv sync --locked`**, which also fails when `uv.lock` is out of date with
     `pyproject.toml`. That is stricter than `--frozen`.
  9. **gitleaks runs from its release tarball** (v8.30.1, SHA-256 checked against the release's
     `checksums.txt`) instead of `gitleaks-action`, so no third-party action and no licence key.
  10. **pip-audit audits `uv export` output** (hashed requirements, `--disable-pip
      --require-hashes --strict`), so it audits exactly what `uv.lock` pins.
  11. **mypy covers `scripts/` as well as `src/`.**
  12. **The SBOM comes from `uv export --format cyclonedx1.5`** in `make release-dry`, so no extra
      SBOM tool is needed.
  13. **uv is pinned** to `>=0.12.9,<0.13` (`[tool.uv] required-version`, and `version` in CI).
- **Consequence:** The toolchain is reproducible from `uv.lock`, and CI and local runs use the same
  make targets. A change to any (A) item needs owner approval and an ADR update.

## ADR-0003: Output schema versioning

- **Date:** 2026-10-02. **Status:** Accepted (owner approved 2026-10-02; it defines output file
  formats, a public interface).
- **Context:** Every output format needs a JSON Schema that CI checks. Vulnerability-management
  teams and CI pipelines will parse the outputs, so changes must be visible and deliberate.
- **Options:** (a) one tool version for everything; (b) an independent SemVer `schema_version` per
  format; (c) date-based schema versions.
- **Decision:** (b).
  - Each format fixproof defines (the evidence bundle, its SHA-256 manifest, the gate result, and
    the `fix.yaml`, `scope.yaml` and `closed.yaml` inputs; the exact set is fixed in M1) carries a
    top-level `schema_version` (SemVer). Its schema is at
    `src/fixproof/schemas/<format>.schema.json`, inside the package so the CLI can validate its
    own output at run time, with `$id` ending in `/<format>/<schema_version>`.
  - MAJOR: a field is removed or renamed, or a meaning or allowed value changes. MINOR: an
    optional field is added. PATCH: descriptions or docs only. A MAJOR or MINOR bump is a
    public-interface change and needs an ADR and owner approval.
  - Schemas are generated from the pydantic models and committed. A test fails when the committed
    schema differs from the generated one.
  - Standard formats are versioned by their standards: OpenVEX by the pinned spec version
    (ADR-0002 item 1) and CycloneDX by `specVersion` (item 2). Each is validated only against
    its official schema, vendored at `src/fixproof/schemas/official/<format>.schema.json`.
    Changing a pin needs an ADR.
  - Example outputs are at `examples/<format>/*.json`. `scripts/validate_outputs.py` (CI job
    `schemas`) validates each one against every schema present for its format and fails a format
    that has none.
  - Schema versions are independent of the package version. The first schemas ship in M1 at
    `1.0.0`.
- **Consequence:** A consumer can tell from `schema_version` whether it can read a file. Drift
  between models and schemas fails CI. Bumps are rare and deliberate.

## ADR-0004: Commit rules and how they are enforced

- **Date:** 2026-10-02. **Status:** Accepted (owner approved 2026-10-02; the same rules the owner
  accepted for controlproof on 2026-09-29).
- **Context:** Commits are authored by the owner alone, and their subjects should show which
  milestone each change serves. The rules must hold locally and in CI.
- **Decision:**
  - Subject: Conventional Commits with a milestone scope, `type(scope): summary`. Types feat, fix,
    test, docs, refactor, perf, build, ci, chore. Scope `M<n>` or `infra`. The summary starts
    with a non-space and is at most 71 characters.
  - Rejected anywhere in the message: any `Co-authored-by:` trailer (the owner is the only
    author), any line that starts with "Generated with" or "Generated by" (tool footers), and the
    robot emoji.
  - The rules live once, in `scripts/commit_rules.py`. The commit-msg hook (activated by `make
    setup`) and the CI job `commit-hygiene` (`scripts/check_commits.py`) both import them, so they
    cannot drift. The message is cut at git's scissors line (`# ---...--- >8 ---...---`), because
    `git commit --verbose` appends the diff below it.
  - `check_commits.py` checks `base..head`. When base is missing or all zeros (a push that
    created a branch), it checks the commits on head that are not on `origin/main`, or every
    commit when `origin/main` does not exist. A base git cannot resolve is exit 2, never a pass.
  - Merge commits get the same subject rule. Prefer squash or rebase merges on GitHub.
- **Consequence:** A local bypass (`--no-verify`) is still caught in CI. GitHub's default merge
  commit message ("Merge pull request #...") would fail `commit-hygiene` on `main`. The owner's
  `Initial commit` (`ad1835e`) predates the rules and is already on `origin/main`, so the range
  check never reaches it.

## ADR-0005: M1 data contracts, input formats and the OpenVEX writer

- **Date:** 2026-10-02. **Status:** Proposed (input file formats and the VEX output are public
  interfaces).
- **Context:** M1 is the data model, the `fix.yaml` and `scope.yaml` schemas and an OpenVEX writer
  with schema validation. OQ-1, OQ-2 and OQ-6 are answered (SPEC_NOTES §14). Facts used: CVE id
  pattern (SPEC_NOTES §2), OpenVEX v0.2.0 (§1), purl canonical form (§5), OCI references (§15).
- **Decision:**
  1. **`fix.yaml`** (format `fix`, `schema_version` 1.0.0). Unknown keys are errors.
     - `cve` (required): the CVE id, pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`. It must equal the
       `--cve` given on the command line, so a fix file for another CVE can never prove this one.
     - `packages` (required, at least one): each has `ecosystem` (`deb`, `rpm`, `apk`, `pypi`,
       `npm` or `maven`: the purl type names), `namespace` (required, optional or forbidden
       exactly as the purl type definition says: required for deb, rpm, apk and maven, optional
       for npm, forbidden for pypi), `name`, `fixed_version` (required) and `fixed_vers`
       (optional vers string whose type equals the ecosystem, for backports).
     - Meaning: an installed version V is fixed when V >= `fixed_version` or V is inside
       `fixed_vers` (comparison per ecosystem arrives in M3). M1 checks vers syntax only
       (scheme, type, comparators, percent-encoding); the §5.4 ordering checks need the M3
       comparators.
     - Several packages cover a fix shipped in several binary packages (for example `libssl3`
       and `openssl`).
  2. **`scope.yaml`** (format `scope`, `schema_version` 1.0.0). Unknown keys are errors.
     - `registries` (required): registry hosts (`host[:port]`) fixproof may read images from.
       This is the allowlist: an image from any other registry, explicit or found in a cluster,
       is never pulled and gets `unknown` with the reason "registry not in scope".
     - `images` (optional): full references `registry/repository@sha256:<64 hex>`. The registry
       host is required (no Docker Hub defaulting) and must be in `registries`; duplicates are
       errors.
     - `clusters` (optional): `context` (kubeconfig context name) and `namespaces` (at least
       one). Name validation against Kubernetes rules is M4.
     - At least one of `images` and `clusters` is non-empty.
  3. **Data model** (pydantic v2, frozen): `ImageRef(registry, repository, digest)`;
     `ImageAsset(image)`; `WorkloadAsset(cluster, namespace, pod, container, image | None)`;
     `MethodResult(asset, method, status, detail, raw_ref)` with `method` in `grype`,
     `sbom_version` and `status` in `present`, `not_present`, `error` (the planned contract plus
     `method`, so a result says which method produced it); `Verdict` in `fixed`,
     `still_affected`, `unknown`; `AssetVerdict(asset, verdict, reason, results)`. The rule that
     combines results (`verdict.py`) is M2.
  4. **OpenVEX document** (one per run):
     - `@context` `https://openvex.dev/ns/v0.2.0`; `version` 1; `author` supplied by the caller
       (required, non-empty); `timestamp` from an injected clock, UTC, RFC 3339 with `Z` and
       whole seconds; `tooling` `fixproof <version>` (Syft, Grype and DB versions join in M2).
     - `@id` = prefix + `vex-` + the first 32 hex digits of the SHA-256 of the canonical document
       without `@id`. The default prefix `https://openvex.dev/docs/fixproof/` uses OpenVEX's
       shared namespace; a caller may pass its own prefix. Same inputs, same `@id`.
     - One statement per distinct image digest, sorted by product `@id`. `vulnerability.name` is
       the CVE id. The product `@id` and `identifiers.purl` are the canonical OCI purl: name = the
       last repository segment, lowercased; version = the digest; qualifier `repository_url` =
       `registry/repository`. `subcomponents` are the unversioned package purls from `fix.yaml`.
     - Status per OQ-2: `fixed` -> `fixed`; `still_affected` -> `affected` with
       `action_statement` "Upgrade <package> to <fixed_version> or later" (plus the backport
       ranges when given); `unknown` -> `under_investigation`. `status_notes` carries the verdict
       reason. The writer has no path that produces `not_affected`, and a test proves it.
     - Workloads whose image digest is unknown get no statement (a statement needs a product);
       they stay in the run report and the evidence bundle. Two different verdicts for the same
       digest are an error, never resolved by picking one.
     - Output: UTF-8 JSON, sorted keys, 2-space indent, trailing newline. Before writing, the
       document is validated against the vendored official schema with format checking on; an
       invalid document raises an error and nothing is written.
  5. **purls are built by fixproof** (`purl.py`) for the seven types it emits (oci, deb, rpm,
     apk, pypi, npm, maven), following the v1.0.1 encoding and build rules, and tested against
     the official `build` vectors for those types, vendored with their SHA-256 under
     `tests/fixtures/purl-spec/` (MIT, licence kept).
  6. **Schemas and examples:** the official OpenVEX schema is vendored at
     `src/fixproof/schemas/official/openvex.schema.json` (CC0-1.0; a test pins its SHA-256 to the
     ADR-0002 value). `fix.schema.json` and `scope.schema.json` are generated from the models and
     committed (a test fails on drift). Examples: `examples/openvex/*.json` (golden output from
     fixed synthetic verdicts, regenerated with `FIXPROOF_UPDATE_GOLDEN=1 make test`),
     `examples/fix/*.yaml` and `examples/scope/*.yaml`. `scripts/validate_outputs.py` learns to
     read `.yaml` examples.
  7. **No CLI command in M1.** `verify` arrives with the first end-to-end path in M2.
  8. **Errors:** `FixproofError` base; `InputError` (file, field and reason) for bad `fix.yaml`
     or `scope.yaml`; `OutputValidationError` when the VEX fails its schema.
  9. **Format set** (ADR-0003): inputs `fix`, `scope` (M1) and `closed` (M5); outputs `openvex`
     (M1), `bundle` and `manifest` (M2), `gate-result` and `cyclonedx` (M5). Each schema lands
     in its milestone.
- **Consequence:** M1's golden VEX files exercise all three statuses and validate against the
  official schema with formats checked. `fix.yaml`, `scope.yaml` and the VEX layout become public
  interfaces at 1.0.0; changing them needs an ADR.

## ADR-0006: M1 runtime dependencies

- **Date:** 2026-10-02. **Status:** Proposed (new runtime dependencies need owner approval).
- **Decision:** add, all MIT:
  - `pydantic>=2.13`: data contracts (planned).
  - `pyyaml>=6.0.3`: reading `fix.yaml` and `scope.yaml` with `safe_load` only.
  - `jsonschema>=4.26`: moves from dev to runtime, to validate the VEX before it is written.
  - `rfc3339-validator>=0.1.4`, `rfc3986-validator>=0.1.1`, `rfc3987-syntax>=1.1.0` (pulling
    `six` and `lark`): without them jsonschema silently skips the `date-time`, `uri` and `iri`
    formats the OpenVEX schema uses (SPEC_NOTES §1). They are jsonschema's own `format-nongpl`
    choices; the alternative `rfc3987` is GPL-3.0-or-later.
  - Dev: `types-pyyaml`.
- **Not added:** `packageurl-python`, which the plan lists. Version 0.17.6 does not produce the
  v1.0.1 canonical form for qualifier values (SPEC_NOTES §5), and M1 only builds purls. Whether it
  parses Syft's purls in M2 (it passes every official parse test) is decided then.
- **Consequence:** PyYAML and three small format validators join the plan's list. The validators
  make the success test's "validates against the pinned OpenVEX schema" check dates and IRIs, not
  just shapes.
