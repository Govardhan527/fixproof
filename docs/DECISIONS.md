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

- **Date:** 2026-10-02. **Status:** Accepted (owner approved 2026-10-02; input file formats and
  the VEX output are public interfaces).
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
- **Amendment 1** (2026-10-02, from the M1 scope review; owner approved 2026-10-02). The loaders
  are stricter than items 1 and 2 said, and this records it:
  - `fix.yaml`: each package (by its purl) may be listed once, and `fixed_vers` may not be `*`.
    vers allows `*`, but as a fixed range it would mark every version fixed, which no fix can
    prove.
  - `scope.yaml`: registries, images, cluster contexts and each cluster's namespaces may each be
    listed once.
  - Assets carry a `kind` discriminator (`image` or `workload`). No M1 output contains it; it
    becomes public with the M2 evidence bundle, and that ADR records it.

## ADR-0006: M1 runtime dependencies

- **Date:** 2026-10-02. **Status:** Accepted (owner approved 2026-10-02).
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
  **M2 follow-up (2026-10-02):** still not added. M2 needs only a purl's type, namespace, name
  and version, which `purl.identity` parses per the spec and passes all 43 official parse
  vectors for the seven types; one small function is cheaper than a dependency.
- **Consequence:** PyYAML and three small format validators join the plan's list. The validators
  make the success test's "validates against the pinned OpenVEX schema" check dates and IRIs, not
  just shapes.

## ADR-0007: M2 design: two methods per image, the verdict table and the evidence bundle

- **Date:** 2026-10-02. **Status:** Accepted (owner approved 2026-10-02, with Q1 and Q2 answered
  as proposed: disagreement gives `unknown`; PyPI comparison moves into M2).
- **Context:** M2 is image-level verification with both methods on 8 fixture images built in CI
  from pinned Dockerfiles; done when the truth-table test covers every agree and disagree
  combination. Facts: SPEC_NOTES §12 and §17 (Syft, Grype), §5 (vers containment), §9 (PEP 440).
- **Decision:**
  1. (Q1, answered) **Verdict table.** The plan's rule ("both say not present -> fixed; any says present ->
     still_affected; disagreement or failure -> unknown") does not say which wins when one method
     says present and the other says not present. Proposed, for the 9 combinations of
     `present` (P), `not_present` (N) and `error` (E):

     | grype | sbom_version | verdict | reason |
     |---|---|---|---|
     | N | N | fixed | both methods agree the vulnerable component is gone |
     | P | P | still_affected | both methods find it |
     | P | E | still_affected | Grype finds it; the SBOM method failed (named) |
     | E | P | still_affected | the SBOM method finds it; Grype failed (named) |
     | P | N | unknown | the methods disagree (both details given) |
     | N | P | unknown | the methods disagree (both details given) |
     | N | E | unknown | the SBOM method failed, so `fixed` cannot be proven |
     | E | N | unknown | Grype failed, so `fixed` cannot be proven |
     | E | E | unknown | both methods failed |

     `still_affected` needs positive evidence and no contradicting evidence; a contradiction is
     `unknown`, never `fixed` and never `still_affected`.
  2. (Q2, answered) **Version comparison in M2.** The SBOM method compares versions, but the comparators are
     M3. Proposed: M2 adds the comparator interface and PyPI only (`packaging`, already in the
     planned stack, PEP 440 per SPEC_NOTES §9) and vers containment (§5); the fixtures use a real
     PyPI advisory (CVE-2023-32681, `requests` >= 2.3.0, < 2.31.0, SPEC_NOTES §17). dpkg, rpm,
     apk, npm and Maven stay in M3 as planned; until then a package in another ecosystem makes
     the SBOM method return `error` (so the verdict is `unknown`, never `fixed`).
  3. **Method `grype`:** run `grype registry:<registry>/<repository>@<digest> -o json` on the
     image itself (not on fixproof's SBOM), with `GRYPE_DB_AUTO_UPDATE=false` (no download during
     a run) and `GRYPE_CHECK_FOR_APP_UPDATE=false` (no update check, no telemetry). `present` when
     any match has `vulnerability.id` equal to the CVE or lists it in `relatedVulnerabilities`
     (PyPI matches carry the GHSA id with the CVE only there, SPEC_NOTES §17); `not_present`
     when Grype exits 0 with no such match; `error` otherwise (non-zero exit, unparsable output,
     missing or stale DB). Grype's own DB age check (default 120 hours) stays on, so a stale DB
     gives `unknown`, not `fixed`. The DB used is read from Grype's `descriptor.db.status`.
  4. **Method `sbom_version`:** run `syft registry:...@<digest> -o json` with
     `SYFT_CHECK_FOR_APP_UPDATE=false` and `SYFT_FILE_METADATA_SELECTION=none` (no file listing;
     file contents are off by default and stay off). Select artifacts whose purl has the fix package's
     type, namespace and name (purl rules, version and qualifiers ignored). `present` when any
     selected artifact's version is neither >= `fixed_version` nor inside `fixed_vers`;
     `not_present` when none is (including when the package is absent); `error` when Syft fails,
     its output is not schema 16.x, or a version cannot be compared.
  5. **Independence, stated honestly:** both tools catalogue with Syft code (Grype embeds Syft),
     so a package Syft cannot see is invisible to both. What differs is the decision: Grype's
     vulnerability data against fixproof's comparison with the claimed fix. The docs say so.
  6. **Digest and platform:** the requested digest must equal the scanned `manifestDigest` or
     appear in `repoDigests`, or the method returns `error`. Given a multi-platform index, both
     tools scan the host platform only (SPEC_NOTES §17), so the bundle records the scanned
     platform and manifest digest, and the docs say a verdict covers that platform.
  7. **Evidence bundle** (formats `bundle` and `manifest`, 1.0.0), written to `--out DIR`, which
     must not exist or be empty (never overwritten):
     - `openvex.json` (ADR-0005);
     - `bundle.json`: run times from the injected clock, fixproof version, the CVE, SHA-256 of
       `fix.yaml` and `scope.yaml`, tool versions (Syft version and JSON schema; Grype version,
       DB schema version, build time and checksum), and per asset the verdict, reason and both
       `MethodResult`s (asset `kind` included, as ADR-0005 Amendment 1 said);
     - `raw/<asset-index>-<method>.json`: the tools' JSON with the raw image config (which holds
       the image's environment variables), raw manifest, labels, annotations, `files` and the
       local DB `path` removed, so nothing from an image layer except package metadata is stored;
     - `manifest.json`: SHA-256 of every other file, sorted by path.
  8. **CLI `fixproof verify --cve ID --fix FILE --scope FILE --out DIR --author TEXT [--json]`.**
     M2 verifies `images`; a scope with `clusters` is an error until M4 (no silent skipping).
     Exit codes: 0 every asset `fixed`; 1 any `still_affected`; 2 no `still_affected` but any
     `unknown`; 3 bad input or usage. `--json` prints a summary (verdict counts and per-asset
     verdicts) to stdout. Syft and Grype are found on `PATH`; their versions are recorded, not
     enforced, and output from another major JSON schema is an `error`.
  9. **Fixtures (8 images, `tests/fixtures/images/<name>/Dockerfile`)**, each `FROM
     python:3.12-slim-bookworm@sha256:54c85f3c...` (pinned index digest, looked up 2026-10-02):
     `requests` 2.30.0 (still_affected); 2.25.1 (still_affected); 2.31.0 (fixed); 2.32.x pinned
     (fixed); absent (fixed); 2.31.0 system-wide plus 2.30.0 in a venv (still_affected); 2.30.0 in
     a venv only (still_affected); and the 2.31.0 image pushed to a second registry that needs
     credentials fixproof is not given (unknown). A second `fix.yaml` claiming `fixed_version`
     2.32.0 run against the 2.31.0 image gives the real disagreement (unknown).
  10. **CI integration job:** `registry:2` (pinned digest) as an open and an authenticated
      service, Syft and Grype pinned by checksum, `grype db update` then status recorded, the 8
      images built and pushed, `fixproof verify` run, verdicts and VEX validity asserted. The
      truth-table unit test (done-criterion) uses fake method results and needs none of this.
  11. **Dependencies:** `typer` (CLI) and `packaging` (PEP 440), both in the planned stack.
- **Consequence:** the verdict rule, the bundle layout and the CLI become public at 1.0.0.
- **Amendment 1** (2026-10-02, from the M2 scope review; Accepted: the owner approved it on
  2026-10-02 by asking to close M2). Interface details built in M2
  that items 7 and 8 did not spell out:
  - `fixproof --version` prints `fixproof <version>` and exits 0.
  - `bundle.json` carries `summary`: the count of `fixed`, `still_affected` and `unknown`.
  - Each `manifest.json` entry carries `size` (bytes) as well as `path` and `sha256`.
  - The stored tool output also drops each tool's own `descriptor.configuration`, which can hold
    registry credentials (SPEC_NOTES §17), on top of the fields item 7 lists.
  - `verify --json` prints `{cve, out, summary, assets: [{asset, verdict, reason}]}`. As an output
    format it has a model (`fixproof.report`), a generated schema (`verify-summary`,
    `schema_version` 1.0.0) and an example, as ADR-0003 requires.

## ADR-0008: Live checks against public images

- **Date:** 2026-10-02. **Status:** Accepted (the owner asked for both on 2026-10-02: a run
  against real public images now, and a scheduled job that keeps doing it).
- **Context:** the unit tests use synthetic data by design, and the integration job builds its
  own images so their verdicts are known in advance. Neither shows fixproof on images someone
  else built. Ground truth is the hard part: a check is only useful when the expected verdict
  comes from a source independent of fixproof and its tools.
- **Decision:**
  1. A `live` test marker and `tests/live/`: `fixproof verify` with real Syft and Grype and the
     Grype DB as published that day, against public Docker Hub images pinned by digest, read
     anonymously (`DOCKER_CONFIG` empty). `make live` runs them; `make test` and the push CI
     exclude them. Without the scanners on PATH they skip locally and fail in CI.
  2. Cases, each with an independent source for its expected verdict (SPEC_NOTES §19):
     - CVE-2023-32681 (`requests`) on `certbot/certbot` v2.6.0 (certbot pins `requests==2.28.2`:
       `still_affected`), v2.7.0 (`2.31.0`, the first fixed release: `fixed`) and v5.8.0
       (`2.34.2`: `fixed`).
     - CVE-2023-4911 (glibc, in CISA KEV) on `debian:12.0-slim` (`libc6 2.36-9`, before Debian's
       fix `2.36-9+deb12u3`): `still_affected`, because Grype finds it even though fixproof
       cannot compare Debian versions until M3; and on the current `python:3.12-slim-bookworm`
       (Debian 12.15, fix installed): `unknown`, because without the comparator fixproof will
       not call it `fixed`. M3 changes that expectation to `fixed`, on purpose.
  3. `.github/workflows/live.yml` runs them every Monday at 06:17 UTC and on manual dispatch,
     after installing the pinned scanners and downloading that day's DB. A changed verdict
     fails the run. GitHub emails scheduled-run failures to whoever last edited the cron line,
     and, because the repository is public, disables the schedule after 60 days without
     repository activity (SPEC_NOTES §19).
  4. `scripts/install_scanners.sh` installs the pinned Syft and Grype for both workflows, so
     their checksums live in one place.
  5. Each later milestone adds live cases for what it builds: M3 real Debian, Alpine and RPM
     images with OS-package CVEs; M4 the kind cluster; M5 the live CISA KEV feed.
- **Consequence:** fixproof is exercised weekly on images it did not build, against current
  advisory data. Anonymous Docker Hub reads are rate-limited, so a failed fetch shows up as an
  `unknown` verdict and a failed run, never as a pass.
- **Amendment 1** (2026-10-02, from the M3 scope review; owner approved 2026-10-02). Live cases
  may also read public images from other registries, read anonymously and pinned by digest, and
  may cover application packages as well as OS packages. First use: CVE-2021-44228 (Log4Shell)
  on `ghcr.io/christophetd/log4shell-vulnerable-app`, whose `log4j-core` version is known from its
  build (SPEC_NOTES §19). The scan is static: nothing in the image is run.

## ADR-0009: M3 version comparators

- **Date:** 2026-10-02. **Status:** Accepted (the owner asked to start M3 with OQ-4 answered (b)
  on 2026-10-02; no public interface changes; the one new dependency is the dev-only oracle
  OQ-4 (b) names).
- **Context:** the SBOM method compares versions per ecosystem. PyPI exists (ADR-0007 Q2); M3 adds
  dpkg, rpm, apk, npm and Maven, each passing a spec-derived table that includes epochs and
  pre-releases. Facts: SPEC_NOTES §6 to §11.
- **Decision:**
  1. One comparator class per ecosystem in `fixproof.versions`, behind the existing `Comparator`
     protocol. Each validates versions against its own grammar; an invalid version raises
     `VersionError`, so the SBOM method reports `error` and the verdict is `unknown`, never
     `fixed`.
  2. **dpkg:** Debian Policy §5.6.12 (§6), written here. `python-debian` (GPL-2.0-or-later) is a
     dev-only dependency used as an oracle: a test compares the two on a seeded, generated corpus
     and on the policy's examples. `src/` never imports it (a test checks).
  3. **rpm:** `rpm-version(7)` (§7): epoch, version, release, `~` and `^`, segment rules.
     Versions are `[epoch:]version[-release]`.
  4. **apk:** apk-tools v3.0.8 behaviour (§8), re-implemented, never copied. Versions with a
     leading-zero digit group after a `.` (such as `1.05`) or a `~hash`, where apk-tools v2
     (Alpine 3.20 to 3.22) and v3 (3.23 onward) can disagree, raise `VersionError`.
  5. **npm:** SemVer 2.0.0 precedence (§10), strict syntax; build metadata ignored.
  6. **Maven:** a port of Apache Maven 3.9.16's `ComparableVersion` (Apache-2.0), the comparator
     behind the POM reference's version order specification (§11). Where the reference and the
     code disagree (only on `_`), versions containing `_` raise `VersionError`.
  7. **Test tables:** each spec's own examples, plus rule-derived cases for epochs, pre-releases
     and the edge cases above. Licence-compatible upstream test vectors are vendored as data
     with their licence: Maven's `ComparableVersionTest` (Apache-2.0) and node-semver's
     comparison fixtures (ISC). GPL-licensed test data (dpkg, rpm, apk-tools) is never copied
     into the repository; agreement with it is checked during development and recorded in
     SPEC_NOTES.
  8. **Live data (ADR-0008 item 5):** the live suite gains real Debian, Alpine and RPM-based
     images with real OS-package CVEs, and CVE-2023-4911 on `python:3.12-slim-bookworm` changes
     from `unknown` to `fixed`.
- **Consequence:** every ecosystem `fix.yaml` accepts can now prove `fixed`. apk versions in the
  v2/v3 grey zone stay `unknown` until a later decision.

## ADR-0010: M4 design: Kubernetes inventory and a verdict per workload

- **Date:** 2026-10-03. **Status:** Accepted (owner approved 2026-10-03).
- **Context:** M4 is the Kubernetes inventory on kind, mapping pods to image digests and giving a
  verdict per workload; done when SUCCESS TEST step 1 passes (6 workloads: exactly 2 `fixed`,
  3 `still_affected` with image digests and pod names, 1 `unknown` with the reason). OQ-5 chose
  the unreadable workload: an image in a registry fixproof has no credentials for. Facts:
  SPEC_NOTES §12.
- **Decision:**
  1. **Inventory** (`fixproof.inventory`): for each `clusters[]` entry, load that kubeconfig
     context (`KUBECONFIG` or `~/.kube/config`, the standard places), list the pods in each
     listed namespace, and turn every container and init container into a `WorkloadAsset`
     (cluster, namespace, pod, container, image). The image comes from the container status
     `imageID` (`registry/repository@sha256:…`). Ephemeral debug containers are skipped.
  2. **Owner:** follow the pod's controller reference; a ReplicaSet is read once more to reach
     its Deployment. The result (for example `Deployment/payments-api`) goes in a new optional
     `owner` field of `WorkloadAsset`.
  3. **No guessing:** a container with no usable `imageID` (still waiting, or an image with no
     repository digest) gets `unknown` with the reason, and so does an image whose registry is
     not in `registries` (it is never pulled).
  4. **Each image is scanned once**, however many workloads run it; every workload takes that
     image's verdict and points at the same raw evidence. VEX stays one statement per image.
  5. **`scope.yaml`:** `clusters` is accepted (the format is unchanged, ADR-0005); `images` and
     `clusters` may be combined.
  6. **Output:** the human output lists each workload as `cluster/namespace/pod/container` with
     its owner and image digest. `verify-summary` 1.1.0 and `bundle` 1.1.0 add the optional
     workload fields (MINOR bumps, ADR-0003). Exit codes are unchanged.
  7. **Least privilege:** `deploy/kubernetes/fixproof-reader.yaml` ships a ServiceAccount, a
     namespaced Role with `get` and `list` on `pods` (core) and `replicasets` (apps) and nothing
     else, and a RoleBinding. The docs show how to give fixproof a kubeconfig for that account.
  8. **Dependency:** `kubernetes` 36.0.3 (Apache-2.0), as planned, with the transitive packages
     listed in SPEC_NOTES §12.
  9. **Tests:** unit tests use a fake Kubernetes API. The CI `integration` job creates a kind
     v0.33.0 cluster (node image pinned by digest) wired to the open and the credentialed test
     registries the kind way (SPEC_NOTES §12), deploys the 6 success-test workloads in their own
     namespace, and runs `fixproof verify` with a kubeconfig for the `fixproof-reader` account
     and no registry credentials, asserting 2 / 3 / 1 with digests, pod names and the reason.
     A second namespace runs workloads from real public images (certbot v2.6.0 and v2.7.0) for
     the live-data criterion (ADR-0008 item 5). The cluster setup lives in a script that
     `make demo` reuses in M6.
- **Consequence:** fixproof reads running clusters with get and list on two resource types only,
  never pulls from a registry outside the allowlist, and reports pods it cannot resolve as
  `unknown`.
- **Amendment 1 (2026-10-03, implementation detail; confirmed by the owner 2026-10-03):** item 7's
  manifest is two files in `deploy/kubernetes/`, not one. `fixproof-reader.yaml` holds the
  `fixproof` namespace and the `fixproof-reader` ServiceAccount (no mounted token);
  `fixproof-reader-role.yaml` holds the Role and the RoleBinding with no namespace, so the same
  file is applied to each namespace in scope with `kubectl apply -n`. One file cannot do both,
  because kubectl refuses `-n` for an object that names another namespace (SPEC_NOTES §12). The
  permissions are exactly as accepted: get and list on pods and replicasets, nothing else.
  Two further details for the same confirmation: `fixproof-reader.yaml` also creates the
  `fixproof` Namespace object the account lives in; and the demo script pins kubectl v1.37.1
  (checksum in SPEC_NOTES §12) next to kind, a setup tool like kind, not a runtime dependency.
  Item 8's transitive packages are listed with versions and licences in SPEC_NOTES §16.
- **Amendment 2 (2026-10-03, accepted: the owner, "I need minikube and docker nodes"): read
  cri-dockerd image IDs.**
  - *Why:* a node that runs Docker Engine through cri-dockerd (for example minikube with
    `--container-runtime=docker`; correction 2026-10-03: minikube's own default is containerd,
    SPEC_NOTES §12) reports `imageID` as `docker-pullable://<RepoDigests[0]>`, with
    Docker's familiar names (`nginx@sha256:…`). Item 1 accepts only `registry/repository@sha256:…`,
    so every workload on such a node is `unknown` today: no value for those users (SPEC_NOTES §12).
  - *Change:* strip `docker-pullable://`, expand the familiar name with Docker's own rule
    (SPEC_NOTES §12, distribution/reference v0.6.0), then parse it as now. `docker://sha256:…`
    (no repository digest) stays `unknown`. Nothing else changes: same RBAC, same allowlist.
  - *Proof:* unit tests for the prefix and every normalisation branch; and a real-node test, a
    CI job on minikube (pinned by version and checksum, Docker driver, Docker runtime) running
    two certbot releases by digest and one by short name and tag, expecting `still_affected`,
    `fixed`, `still_affected`. minikube would be a new CI tool, like kind.

## ADR-0011: After M4: CRI-O nodes and scanning several images at once

- **Date:** 2026-10-03. **Status:** Accepted (owner: "Support for CRI-O and scan several images";
  `--jobs` with default 4 chosen 2026-10-03).
- **Context:** the M4 value test listed both as gaps a real user would hit: nodes running CRI-O
  were untested, and images were scanned one after another, so large clusters were slow
  (PARKED, 2026-10-03).
- **Decision:**
  1. **CRI-O.** CRI-O v1.35 reports a container's `ImageRef` as the image's first repository
     digest in full (`docker.io/library/python@sha256:…`), or the bare image ID when there is none
     (SPEC_NOTES §12). fixproof reads the first like containerd's and reports the second as
     `unknown`, so no parsing change is expected. Proof on a real node: the minikube CI job runs
     for both `--container-runtime=docker` and `--container-runtime=cri-o`, with the same
     workloads and checks, plus the raw image ID forms each runtime reports.
  2. **`verify --jobs N`** (default 4, at least 1): up to N distinct images are scanned at the same
     time, each with Syft and Grype one after the other as now. Inventory runs first; the
     verdicts, the report and the evidence bundle are the same, in the same order, for any N.
     Measured locally: one scan peaks at about 250–315 MB, and three Grype runs at once on the
     same database all succeed (SPEC_NOTES §12). `--jobs 1` keeps the old behaviour. A public
     CLI addition (MINOR); no output format changes.
- **Consequence:** CRI-O, containerd and Docker Engine nodes are all proven on real nodes in CI;
  a cluster with many images is scanned several images at a time.

## ADR-0012: M5 design: release gate, KEV enrichment, HTML summary, CycloneDX VEX

- **Date:** 2026-10-03. **Status:** Accepted (owner answered the four questions below,
  2026-10-03).
- **Context:** M5 is "CI gate, KEV enrichment, HTML report, CycloneDX VEX", done when SUCCESS TEST
  steps 2 and 3 pass. Facts: SPEC_NOTES §3 (KEV), §4 (CycloneDX 1.6.2 and the library), §12
  (image source schemes of the pinned tools).
- **Decision:**
  1. **`fixproof gate --closed closed.yaml --image IMAGE`.** For every closed CVE it runs both
     methods on the image and the verdict rule, as `verify` does. Exit codes (owner: "exit 2,
     fail the build"): 0 every closed CVE proven gone; 1 at least one is back
     (`still_affected`); 2 none back but at least one `unknown`, with the reason; 3 bad input or
     usage. `--json` prints a `gate-result` (1.0.0, schema in `src/fixproof/schemas/`). Human
     output names each CVE, its verdict, reason and KEV status.
  2. **Gate images** (owner: "registry + local builds"): a registry reference pinned by digest
     (allowlist check from a `registries` list in `closed.yaml`), or a just-built image with an
     explicit scheme the pinned tools support: `docker:NAME[:TAG]` (local Docker daemon),
     `docker-archive:PATH`, `oci-archive:PATH`. The result records the exact digest or image ID
     the tools scanned. A tag without a scheme is refused, as in `scope.yaml`.
  3. **`closed.yaml`** (format `closed`, 1.0.0): `schema_version`, optional `registries`, and
     `closed`, a list of `{cve, packages}` where `packages` is exactly `fix.yaml`'s package list.
     Each CVE once.
  4. **KEV** (owner: "download on every run"): `verify` and `gate` fetch the CISA feed (HTTPS,
     timeout 30 s, size limit 16 MB) once per run, validate it against the vendored KEV schema,
     and record its URL, `catalogVersion`, `dateReleased`, retrieval time and SHA-256. For each
     CVE they report whether it is in KEV with `dateAdded`, `dueDate`, `requiredAction` and
     `knownRansomwareCampaignUse`. A failed download or an invalid feed never changes a verdict
     or an exit code: it is recorded as `unavailable` with the reason. Unit tests use an injected
     fetcher (no network); the live suite reads the real feed.
  5. **CycloneDX VEX** (owner: "cyclonedx-lib + stdlib HTML"): `verify` also writes
     `cyclonedx.json`, CycloneDX 1.6 via `cyclonedx-python-lib` 11.12.0 (Apache-2.0; adds
     `license-expression`, `py-serializable`, `sortedcontainers`, `typing_extensions`). One
     `container` component per image (its OCI purl) and one vulnerability entry per image, with
     `analysis.state`: `fixed` -> `resolved`, `still_affected` -> `exploitable` (with response
     `update`), `unknown` -> `in_triage`; `detail` is the reason. `not_affected` and
     `false_positive` are never written. The serial number is derived from the content and the
     timestamp is the run's clock, so output is deterministic. Validated against the official
     1.6.2 schema with its two companion schemas, vendored, before it is written.
  6. **HTML summary:** `verify` writes `report.html`: one self-contained page (inline CSS, no
     JavaScript, no external requests) with the counts, the KEV status, and every asset or
     workload with its verdict, reason and digest. Built with the standard library and
     `html.escape` on every value. Golden-file tested.
  7. **Formats:** `bundle` 1.2.0 and `verify-summary` 1.2.0 add `kev` (MINOR, ADR-0003); the
     bundle gains `cyclonedx.json` and `report.html`, both in the manifest; new formats `closed`
     and `gate-result` 1.0.0.
  8. **Tests:** unit tests for each piece (no network); golden files for CycloneDX and HTML; the
     CI `integration` job gates real fixture images from the local Docker daemon, a
     `docker save` archive and the registry by digest (a reintroduced CVE exits 1, a fixed image
     0, an unreadable one 2); the live suite checks KEV against the live CISA feed.
- **Consequence:** SUCCESS TEST steps 2 and 3 can be checked end to end; every run records the
  KEV feed it used or why it could not.
- **Amendment 1 (2026-10-04, from the M5 scope and spec reviews; confirmed by the owner
  2026-10-04):**
  details the build settled that the items above do not spell out.
  1. *Exit 2 and the SUCCESS TEST wording.* Step 3 says the gate exits "zero otherwise". The
     owner's answer to item 1 ("exit 2, fail the build") reads "otherwise" as "proven gone":
     an image the gate cannot read is not proven clean, so it does not exit 0.
  2. *Two tools, two images.* The verdict rule assumes both methods read the same image. If
     their image IDs differ (a tag moved between the two reads, say), every closed CVE is
     `unknown` with that reason (exit 2), even if one method found the CVE: neither result can
     be tied to the image the user named. It still blocks the release.
  3. *`registry:` prefix.* `--image registry:REF` is accepted as the same as `REF`, matching the
     tools' own scheme; the help text and README say so.
  4. *Recorded fields.* The KEV record also carries the feed's `count` and the entry's
     `vendorProject`, `product` and `vulnerabilityName` (SPEC_NOTES §3). Every method result's
     scan record gains `image_id` (the tools' `imageID`), so `bundle` 1.2.0 has it too.
  5. *The `build` asset kind* (`BuildAsset`, used by `gate`) joins the shared asset union, so the
     `bundle` 1.2.0 schema accepts it; `verify` never writes one, and `gate` writes no bundle.
  6. *Dependencies* (item 5): `cyclonedx-python-lib` also brings `boolean.py` (BSD-2-Clause) and
     `defusedxml` (PSFL); the full list with licences is in SPEC_NOTES §16.
  7. *Vendored official schemas.* The repository's commit text check skips
     `src/fixproof/schemas/official/` only, where every file is a third-party standard pinned by
     SHA-256 in a test (owner, 2026-10-03), because the official CycloneDX schema's own text
     trips it.
  8. *Integration evidence and cisa.gov.* The integration tests check KEV values when the feed is
     reachable and otherwise only that the run says why; the strict KEV checks are in the live
     suite, so SUCCESS TEST evidence never depends on cisa.gov being up.

## ADR-0013: M6 design: `make demo`, docs that match the CLI, hardening, release

- **Date:** 2026-10-04. **Status:** Accepted (owner answered the four questions, 2026-10-04).
- **Context:** M6 is "packaging, docs, demo, hardening only", done when `make demo` runs the
  SUCCESS TEST end to end and the docs match the CLI; the release job comes after that.
- **Decision:**
  1. **`make demo`** (owner: "locally and in CI"): `scripts/demo.sh` installs the pinned scanners,
     updates the Grype DB, brings up the kind demo cluster (`scripts/demo_cluster.sh`), then runs
     the SUCCESS TEST as a user would and checks it (`scripts/success_test.py`): step 1
     `fixproof verify` on the six workloads (exactly 2 / 3 / 1, digests, pod names, the reason);
     step 2 the OpenVEX validates against the pinned schema with no `not_affected`; step 3
     `fixproof gate` on a built image that brings a closed CVE back (non-zero) and on one that
     does not (zero). It prints PASS or FAIL per step and exits non-zero on any failure.
     `make demo-down` removes the cluster and registries. A CI `demo` job runs exactly
     `make demo` on `main` and on dispatch.
  2. **Docs match the CLI:** a unit test compares every option of `verify` and `gate`, every exit
     code and every `make` target the README names with the CLI and the Makefile, both ways.
  3. **Hardening** (owner chose all four):
     - `fix.yaml`, `scope.yaml` and `closed.yaml` over 1 MB, or with YAML anchors or aliases,
       are refused with the reason (exit 3).
     - Every Kubernetes API call has a timeout (10 s to connect, 60 s to read); a slow or silent
       API server ends the run with exit 3 and the reason.
     - Syft and Grype output is read up to 512 MB per run; beyond that the method is an error,
       so the verdict is `unknown` with the reason, never `fixed`.
     - Property-based tests with `hypothesis` 6.168.3 (dev only, MPL-2.0): the six version
       comparators are a total order on generated versions (reflexive, antisymmetric,
       transitive), and the purl and vers parsers never crash or lose round-trips.
  4. **Version and packaging** (owner: "0.1.0"): version 0.1.0, project URLs and keywords in
     `pyproject.toml`; CI builds the wheel and sdist, installs the wheel in a clean environment
     and runs `fixproof --version` and a schema check.
  5. **Release** (owner: "PyPI, TestPyPI first"), after the done-criterion: `.github/workflows/
     release.yml` on tags `v*`: build, CycloneDX SBOM of the package, SHA-256 sums, a GitHub
     release with all of them attached, and PyPI trusted publishing (no stored token) from a
     protected environment: pre-release tags (`v0.1.0rc1`) go to TestPyPI, final tags to PyPI.
     The owner creates the two pending publishers and the GitHub environments; every tag push is
     the owner's call. After the TestPyPI rehearsal, fixproof is installed from TestPyPI and run
     on a real image before the final tag.
- **Consequence:** the SUCCESS TEST is one command anyone can run and CI proves on every change;
  the README is held to the CLI by a test; fixproof refuses or reports, rather than hangs or
  runs out of memory on, hostile or broken inputs; a user can `pip install fixproof`.
- **Amendment 1 (2026-10-04, from the M6 spec and scope reviews; confirmed by the owner
  2026-10-04):**
  1. *Release safety.* The release workflow refuses a tag that is not the project's canonical
     PEP 440 version, refuses a tagged commit that is not on `main` or whose CI run on `main` did
     not pass, sends every pre-release (a, b, rc or dev) to TestPyPI, and never runs two releases
     of one tag at once.
  2. *Rehearsal.* The rehearsal is a release candidate: a commit sets the version to `0.1.0rc1`,
     the tag `v0.1.0rc1` publishes it to TestPyPI, fixproof is installed from there and run on a
     real image, and a second commit sets `0.1.0` for the final tag.
  3. *TestPyPI first, enforced.* The owner adds the PyPI pending publisher only after the
     rehearsal has passed, and gives the `pypi` environment a required reviewer.
  4. *The PyPI page.* The package description is the README, so its links are absolute and the
     install section changes to `pip install fixproof` in the final release commit, not before.
  5. *Details:* standard error is kept to its last 64 KiB; "1 MB" and "512 MB" are 1 MiB and
     512 MiB; vers has no writer in fixproof, so item 3's round-trip covers purls (every type) and
     both parsers are fuzzed for "ValueError only"; `make demo` takes `FIXPROOF_DEMO_DIR`; CI also
     runs `make demo-down`; `make release-dry` builds exactly what the release does.
- **Amendment 2 (2026-10-04, the owner: "i have pypi credentials there use them and same config
  details and owner", pointing at the release setup of their other published package; confirmed
  by the owner 2026-10-04: "Yes Approved").** It
  replaces trusted publishing in item 5 and the TestPyPI parts of Amendment 1, items 1 to 3. This
  departs from the project plan's CI line ("publish with PyPI trusted publishing") on the owner's
  instruction.
  1. *Upload.* Uploading to PyPI is the owner's step, as for their other package:
     `scripts/publish.sh vX.Y.Z` downloads the wheel and sdist that the release workflow attached
     to the GitHub release, refuses them unless that release's `SHA256SUMS` names exactly those
     two files and they match it, runs `twine check --strict`, and uploads them with twine 7.0.0
     and the credentials in the owner's `~/.pypirc` (`--non-interactive`). PyPI therefore gets the
     same bytes as the GitHub release. GitHub holds no PyPI token, and no project tooling reads,
     prints or logs one.
  2. *The workflow* on tags `v*` keeps the Amendment 1 checks (canonical version, commit on a
     green `main`, one release per tag at a time), builds and checks the packages, and creates the
     GitHub release with the packages, the SBOM and the sums. It no longer publishes, so no
     pending publishers or GitHub environments are needed. `scripts/check_package.sh` (the CI
     `package` job, the release and `make release-dry`) also runs `twine check --strict`, so a
     README that PyPI cannot render fails before any tag.
  3. *Rehearsal without TestPyPI.* The owner's configuration is for PyPI, so the tag `v0.1.0rc1`
     makes a GitHub pre-release only. Its wheel is installed in a fresh environment and run on a
     real image, and `scripts/publish.sh v0.1.0rc1` checks the packages and stops: a pre-release
     is never uploaded. Then come the final commit (`0.1.0`, the README install from PyPI), the
     tag `v0.1.0` and the owner's upload, and the release is checked on GitHub, in the tags on
     `origin` and in PyPI's JSON API (each sha256 against `SHA256SUMS`).
  4. *Owner metadata.* The package author is Govardhan Yadava <govardhan@seccrypto.dev>, the
     identity of the owner's PyPI account and of their other package.
  5. *First upload.* A PyPI token can be limited to one project (SPEC_NOTES §18). If the token in
     `~/.pypirc` is limited to the other package, the first upload of `fixproof` is expected to
     be refused and to need a token for the whole account; a token limited to `fixproof` can
     replace it afterwards. *Outcome (2026-10-04):* it did not arise; the token uploaded
     fixproof's first release (SPEC_NOTES §18).

## ADR-0014: M7 item 1: every platform of a multi-platform image is checked

- **Date:** 2026-10-04. **Status:** Accepted (2026-10-04: asked which parked item comes first,
  the owner chose this one and approved the recommended options for all three M7 items; the
  recommendation was to check every platform with no new cluster permission, and to settle the
  details here).
- **Context:** for an image index, Syft and Grype scan the platform of the machine running
  fixproof (SPEC_NOTES §20: the alpine 3.22 index read on a linux/amd64 host gave its amd64
  manifest). A pod on an arm64 node, or fixproof run on an Apple Silicon laptop against an amd64
  cluster, therefore got a verdict about another image than the one in question, and nothing on
  the verdict line said so (the platform was only in the bundle). Reading a node's architecture
  needs `get` on nodes, cluster-wide, which ADR-0010 does not grant.
- **Decision:**
  1. **Listing the platforms.** For an image read from a registry (`verify`'s images and
     workloads, `gate`'s registry images) fixproof first reads the manifest at the digest with
     `crane manifest` (go-containerregistry, pinned v0.22.1): the library Syft and Grype read
     registries with, so the same Docker config, credential helpers and plain HTTP for
     `localhost` apply, and fixproof itself still never reads a registry credential. The bytes
     must hash to the digest. An image manifest is one platform and is checked as before. In an
     image index, every entry whose platform `os` is `linux` is checked through its own manifest
     digest (`registry:REPOSITORY@<entry digest>`), so each tool reads exactly that platform and
     the scanned-digest check (ADR-0007 item 6) holds per platform. BuildKit attestation entries
     (`vnd.docker.reference.type: attestation-manifest`, platform `unknown/unknown`) are not
     platforms and are ignored. Entries for another operating system are named as not checked
     ("fixproof checks Linux platforms only"). An entry that is itself an index, a manifest that
     cannot be read, or one that does not hash to its digest makes the image `unknown` with the
     reason. Without `crane` on `PATH`, a registry image is `unknown` with the reason.
  2. **Choosing platforms.** `scope.yaml` and `closed.yaml` 1.1.0 may list `platforms`
     (`os/arch[/variant]`). Then only the entries of an index matching one of them are checked,
     and the others are named as not in scope; without the list, every Linux entry is checked.
     Matching normalises variants as containerd does (SPEC_NOTES §20: `amd64/v1` is `amd64`,
     `arm64/v8` is `arm64`, `arm` is `arm/v7`). A single-platform image is checked whatever its
     platform. An index with no entry in `platforms` is `unknown` with the reason. Version
     1.0.0 files keep working unchanged.
  3. **One verdict from several platforms** (`verdict.py`, tested exhaustively): each platform
     gets the verdict rule; then any `still_affected` platform makes the image `still_affected`;
     every platform `fixed` makes it `fixed`; anything else is `unknown`. `unknown` on one
     platform is never outweighed by `fixed` on others. The reason starts with each platform's
     verdict, then gives each platform's own reason, then names the platforms not checked. With
     one platform and nothing left out, the reason is exactly as before.
  4. **Output.** `bundle` 2.0.0: each asset has `platforms` (platform, manifest digest, verdict,
     reason, the method results with their raw files, what each tool scanned) and `not_checked`
     (platform, digest, why), in place of 1.x's per-asset `results` and `scanned`. Raw files of
     an image with more than one platform are named `raw/NNN-<os>-<arch>[-<variant>]-<method>.json`.
     `verify-summary` 1.3.0 and `gate-result` 2.0.0 gain each platform's verdict. On the console
     each platform gets its own line under the verdict. The VEX documents keep one statement per
     image, with the combined reason.
  5. **`gate`** lists platforms the same way for a registry image. A local build
     (`docker:`, `docker-archive:`, `oci-archive:`) stays one platform, the one the tools read,
     recorded as before; a multi-platform OCI archive is checked for that platform only, and the
     README says so.
  6. **Install.** `scripts/install_scanners.sh` installs crane next to Syft and Grype, checked
     against the SHA-256 in its release's checksums file.
- **Consequences:** a verdict now covers every Linux platform of the image, or names the ones it
  does not. A typical three-platform image costs one manifest read and six scans instead of two;
  Docker Hub counts manifest reads toward its pull limits, so the README recommends `platforms`
  and a Docker Hub login for large scopes. The README's "One platform per image" limitation is
  replaced. Expected results in the live and integration tests change wherever an image has
  several platforms.
- **Amendment 1 (2026-10-04, from the M7 spec and scope reviews; confirmed by the owner
  2026-10-06: "Approved"):**
  1. *A new pinned tool.* crane joins Syft and Grype in ADR-0002's stack, installed the same way
     (a pinned release, checked against its SHA-256); it is chosen here because it reads
     registries exactly as the two scanners do, so fixproof itself still never reads a credential.
  2. *`--jobs`* (ADR-0011) now counts image platforms scanned at the same time, not images; the
     results stay the same for any value.
  3. *The two tools must read one image in `verify` too.* ADR-0012's rule for `gate` (if Syft and
     Grype report different image IDs, the verdict is `unknown`) now applies to every platform
     checked by `verify` as well; it can only turn a verdict into `unknown`, never `fixed`.
  4. *The variant the tools report* is read from Syft's `architectureVariant` (SPEC_NOTES §20), so
     a single-platform image's platform is recorded in full (`linux/arm/v7`).

## ADR-0015: M7 item 2: managed-cluster sign-in, proven without a cloud account

- **Date:** 2026-10-04. **Status:** Accepted (the owner's approval of the recommended options,
  recorded in ADR-0014; the recommendation was to prove the sign-in mechanisms on kind, since a
  real EKS, GKE or AKS run needs the owner's cloud account, which that approval does not cover).
- **Context:** managed clusters sign kubectl in through a kubeconfig **exec plugin**, a command
  that prints a short-lived token, and cloud registries through a **Docker credential helper**
  named in the Docker config. fixproof had only been run with a token in the kubeconfig and a
  password in `auths`. The Kubernetes client runs exec plugins itself, but when one fails it only
  logs the error (SPEC_NOTES §21), and the run then failed with the API server's bare refusal
  (`401 Unauthorized`, or `403 Forbidden` where anonymous requests are let in).
- **Decision:**
  1. **A failing exec plugin is named.** While the kubeconfig loads, fixproof collects what the
     client logs; a plugin failure stops the run with exit 3 and "cannot sign in to kubeconfig
     context …: its exec plugin failed: …" with the plugin's own message (one line, URL
     credentials masked), said once.
  2. **Proven on kind in CI, with no cloud account:** the reader account's token moved out of
     the kubeconfig into a store an exec plugin reads, with `client.authentication.k8s.io/v1beta1`
     and `v1`, gives the SUCCESS TEST result, and the token appears nowhere in what fixproof
     prints or writes; a plugin that fails gives exit 3 with its message and no evidence. A Docker
     credential helper, named in `credHelpers` and as the `credsStore`, gives crane, Syft and
     Grype the password-protected registry, so the private workload gets a real verdict, and the
     password appears nowhere either. Unit tests run the real client offline against plugins
     that succeed and that fail in each way the client reports.
  3. **The README** says how to point fixproof at a managed cluster and a cloud registry (the
     kubeconfig the cloud's CLI writes; the cloud's own credential helper) and keeps saying
     plainly that EKS, GKE and AKS themselves are not tested.
- **Consequences:** the two mechanisms every managed cluster and cloud registry relies on are
  tested on every push to `main`; what stays unproven is each cloud's own plugin and identity
  mapping, which needs a real account.

## ADR-0016: M7 item 3: an evidence bundle for `gate`

- **Date:** 2026-10-04. **Status:** Accepted (the owner's approval of the recommended options,
  recorded in ADR-0014; the recommendation was an evidence bundle for `gate`, parked 2026-10-04).
- **Context:** `gate` decides whether a release ships, but kept nothing: its console text or
  `--json` scrolled away with the CI log, and the tool output it decided on was gone.
- **Decision:**
  1. `fixproof gate --out DIR` (optional) writes, to a new or empty directory (checked before
     anything is read, exit 3 otherwise; evidence is never overwritten):
     - `gate.json`, format `gate-bundle` 1.0.0: the fixproof version, start and finish times, the
       SHA-256 of `closed.yaml`, the result exactly as `--json` prints it (`gate-result` 2.0.0),
       and an index of the raw files (platform, manifest digest, method, path);
     - `raw/<method>.json`, or `raw/<os>-<arch>[-<variant>]-<method>.json` for an image with
       several platforms: each tool's sanitised output, once per platform and tool however many
       CVEs are closed (the tools ran once);
     - `manifest.json` (`manifest` 1.0.0): the SHA-256 and size of every other file.
  2. The console output and exit codes do not change; without `--out` nothing is written.
  3. No VEX document: a local build has no registry digest to name it by, and the decision is
     the record.
- **Consequences:** a CI job can keep the gate's evidence as a build artifact and check later,
  with the manifest, that it is unchanged.
