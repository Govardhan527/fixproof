# Progress

Tick an item only when its done-criteria pass and the evidence is stored or linked.

## M0: bootstrap

- [x] Repo layout, `pyproject.toml`, `uv.lock`, Makefile, CI workflow, commit-msg hook and PR
      template exist.
- [x] Project docs exist: PROGRESS.md (full milestone list), DECISIONS.md, SPEC_NOTES.md,
      PARKED.md.
- [x] ADR-0001 (licence), ADR-0002 (stack confirmation), ADR-0003 (output schema versioning)
      exist, plus ADR-0004 (commit rules). ADR-0001 is Accepted; ADR-0002 to ADR-0004 are
      Proposed until the owner approves.
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
- [ ] M0 committed on `main`; a clean clone passes `make check`.
- [ ] CI green on GitHub (after the owner says to push).

## M1 (week 2)

Data model, `fix.yaml` and `scope.yaml` schemas, OpenVEX writer with schema validation.
- [ ] Done: golden VEX files validate.
- [ ] OQ-1, OQ-2 and OQ-6 in `docs/SPEC_NOTES.md` §14 answered by the owner (they block M1).
- [ ] OpenVEX schema vendored at the ADR-0002 pin; `format` checking settled (SPEC_NOTES §1).
- [ ] ADR for the M1 data contracts (output formats, input file formats).

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

- **Date:** 2026-10-02. **Current milestone:** M0.
- **Changed:** M0 skeleton (pyproject, uv.lock, Makefile, CI workflow with actions pinned by SHA,
  commit-msg hook + `scripts/check_commits.py` + shared `scripts/commit_rules.py`,
  `scripts/validate_outputs.py`, PR template), ADR-0001 to ADR-0004, SPEC_NOTES from primary
  sources, PARKED.
- **Tests:** `make check` green: 43 unit tests, coverage 100% of `src/`, 0 example files.
- **Waiting on the owner:** git identity for this repository (not set; commits wait for it);
  approval of ADR-0002 to ADR-0004; answers to OQ-1 to OQ-6 (SPEC_NOTES §14).
- **Next step:** show the hook rejecting a commit in this repo, commit M0 in slices, then wait
  for the owner to say push.
