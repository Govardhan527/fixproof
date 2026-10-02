# Progress

Tick an item only when its done-criteria pass and the evidence is stored or linked.

## M0: bootstrap

- [x] Repo layout, `pyproject.toml`, `uv.lock`, Makefile, CI workflow, commit-msg hook and PR
      template exist.
- [x] Project docs exist: PROGRESS.md (full milestone list), DECISIONS.md, SPEC_NOTES.md,
      PARKED.md.
- [x] ADR-0001 (licence), ADR-0002 (stack confirmation), ADR-0003 (output schema versioning)
      exist, plus ADR-0004 (commit rules). All four are Accepted (owner approved ADR-0002 to
      ADR-0004 on 2026-10-02).
- [x] SPEC_NOTES.md lists every spec source in the plan (CVE JSON 5, CISA KEV feed, OpenVEX,
      CycloneDX 1.6, purl and vers, Debian policy, RPM, PEP 440, SemVer and node-semver, Maven),
      plus apk, Kubernetes, Syft, Grype and kind, each with the primary URL and retrieval date,
      or `UNVERIFIED`.
- [x] `make check` is green on the empty skeleton (2026-10-02: 43 unit tests pass, coverage
      100% of `src/`, 0 example files).
- [x] A test commit with a forbidden trailer is rejected by the hook, and
      `scripts/check_commits.py` fails on a crafted bad range in a unit test.
      - [x] Unit test: `tests/test_check_commits.py::test_crafted_bad_range_fails` passes.
      - [x] Hook rejection in a scratch repo:
            `tests/test_commit_msg_hook.py::test_hook_rejects_a_real_commit` passes.
      - [x] Hook rejection shown in this repo (2026-10-02): a `Co-Authored-By:` trailer
            ("forbidden attribution matched: (?im)^co-authored-by:") and the subject "Initial
            setup" ("subject must look like 'feat(M2): short summary'") were both rejected with
            "commit rejected:" and exit 1, and no commit was created.
- [x] M0 committed (2026-10-02): `31007da`..this commit on `main`. A clean clone passes
      `make check` (43 tests; the 44th runs only locally), and `scripts/check_commits.py`
      passes on `origin/main..HEAD`.
- [x] CI green on GitHub (2026-10-02): run 36983082166 on `bc56f42`, all six jobs passed
      (commit-hygiene checked 7 commits, 43 tests, coverage 100%, no leaks, no known
      vulnerabilities).

## M1 (week 2)

Data model, `fix.yaml` and `scope.yaml` schemas, OpenVEX writer with schema validation.
- [x] Done: golden VEX files validate (2026-10-02). `examples/openvex/mixed.json` (all three
      statuses, two pods on one image, a registry outside scope, an unresolved pod) and
      `examples/openvex/single-fixed.json` match the writer byte for byte
      (`tests/test_golden.py`), and `make schemas` validates both against the official OpenVEX
      schema with `date-time`, `uri` and `iri` checked.
- [x] OQ-1, OQ-2 and OQ-6 in `docs/SPEC_NOTES.md` §14 answered by the owner (2026-10-02: the
      recommended options).
- [x] OpenVEX schema vendored at the ADR-0002 pin (SHA-256 pinned by
      `tests/test_validation.py`); `format` checking settled (SPEC_NOTES §1, ADR-0006).
- [x] ADR for the M1 data contracts: ADR-0005 (with Amendment 1) and ADR-0006, Accepted.
- [x] Scope review of the M1 diff (2026-10-02): all in scope; its one finding became ADR-0005
      Amendment 1.
- [x] Spec-source review of the M1 diff (2026-10-02): 18 gaps (16 missing citations, one
      incomplete, vers containment unverified), all closed in SPEC_NOTES §1, §5, §15 and §16. It
      also surfaced a conflict inside vers-spec v1.2.0 about `=`, now recorded in §5.
- [x] CI green on GitHub (2026-10-02): run 36986334645 on `73d64da`, all six jobs passed
      (14 commits checked, 206 tests, 5 example files valid, no leaks, no known
      vulnerabilities).

## M2 (weeks 3-4)

Image-level verification with both methods (Grype match; Syft SBOM version against the fixed
range) on 8 fixture images, built in CI from pinned Dockerfiles.
- [ ] Done: the truth-table test covers every agree and disagree combination.
- [ ] Syft and Grype JSON fields and the Grype DB version verified (SPEC_NOTES §12).
- [ ] Remove the "no integration tests yet" exit-5 allowance from `make integration`.

## M3 (week 5)

Version comparators for dpkg, rpm, apk, PyPI, npm and Maven with spec-derived test tables.
- [ ] Done: each comparator passes its table, including epochs and pre-releases.
- [ ] OQ-4 (dpkg and the GPL) answered; the UNVERIFIED items in SPEC_NOTES §8, §10 and §11
      resolved.

## M4 (weeks 6-7)

Kubernetes inventory on kind; pod to digest mapping; verdict per workload.
- [ ] Done: SUCCESS TEST step 1 passes (2 `fixed`, 3 `still_affected` with image digests and
      pod names, 1 `unknown` with the reason).
- [ ] OQ-5 (the unreadable workload) answered; `imageID` format verified (SPEC_NOTES §12).
- [ ] Read-only Role and RoleBinding YAML shipped.

## M5 (week 8)

CI gate, KEV enrichment, HTML report, CycloneDX VEX.
- [ ] Done: SUCCESS TEST steps 2 and 3 pass (OpenVEX validates against the pinned schema with no
      `not_affected` without evidence; `fixproof gate` exits non-zero on a reintroduced closed
      CVE and zero otherwise).
- [ ] OQ-3 (CycloneDX version) answered.

## M6 (weeks 9-10)

Packaging, docs, demo, hardening only.
- [ ] Done: `make demo` runs the SUCCESS TEST end to end; docs match the CLI.
- [ ] Add the CI `release` job (tag `v*`: build, SBOM, PyPI trusted publishing), only after M6.

## Last session (resume here)

- **Date:** 2026-10-02. **Current milestone:** M1 closed; M2 is next.
- **Changed in M1:** dependencies (ADR-0006); `validation.py` with the vendored official OpenVEX
  schema and format checking; `purl.py` (canonical purls, checked against the official
  purl-spec v1.0.1 build vectors); `model.py`, `vers.py`, `inputs.py` (`fix.yaml` and
  `scope.yaml`, ADR-0005 and Amendment 1); generated `fix` and `scope` schemas with synthetic
  examples; `vex.py` and `canonical.py` (OpenVEX writer); golden VEX files.
- **Tests:** `make check` green: 207 tests locally (206 in CI), coverage 100% of `src/`, 5 example files
  valid. All test data is synthetic (CVE-2099-xxxx, demo package names).
- **Decisions:** owner approved ADR-0002 to ADR-0006 and ADR-0005 Amendment 1; OQ-1, OQ-2 and
  OQ-6 answered with the recommended options.
- **M1 pushed:** CI run 36986334645 on `73d64da` green. The spec-source review's 18 gaps were
  closed in SPEC_NOTES after the push.
- **Open questions still waiting on the owner:** OQ-3 (blocks M5), OQ-4 (blocks M3), OQ-5
  (blocks M4), in `docs/SPEC_NOTES.md` §14.
- **Next steps, in order (M2):**
  1. Verify the Syft and Grype JSON fields, the Grype DB version and build date, and how Grype
     reports a fixed-in version (SPEC_NOTES §12, UNVERIFIED); decide whether `packageurl-python`
     parses Syft's purls (ADR-0006).
  2. Propose the M2 design as an ADR: method contracts, the verdict truth table, the evidence
     bundle and manifest formats (record the asset `kind` field there), the `verify` CLI for
     images, and the 8 pinned fixture Dockerfiles. Wait for approval.
  3. Build `methods/grype.py`, `methods/sbom_version.py` and `verdict.py` test first; wire Syft
     and Grype into the CI `integration` job pinned by checksum; remove the exit-5 allowance.
