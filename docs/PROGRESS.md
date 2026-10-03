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
- [x] Done: the truth-table test covers every agree and disagree combination (ADR-0007 item 1):
      `tests/test_verdict.py` enumerates all 9 outcomes from the enums and checks both
      invariants (2026-10-02).
- [x] Syft and Grype JSON fields, exit codes, DB status and multi-platform behaviour verified
      (SPEC_NOTES §17, 2026-10-02).
- [x] M2 design accepted: ADR-0007 (owner approved 2026-10-02).
- [x] PyPI comparator and vers containment (moved forward from M3 by ADR-0007 Q2), tested on
      the spec's own PEP 440 example ordering.
- [x] Methods `grype` and `sbom_version`, evidence bundle and manifest, `verify` CLI, with
      golden bundle files and end-to-end CLI tests against stand-in tools.
- [x] 8 fixture images and the CI integration job (ADR-0007 items 9 and 10): green in run
      36990675252 on `10db705` (2026-10-02). Real Syft 1.54.0 and Grype 0.119.0 (DB v6.1.9 built
      2026-10-02T06:31:53Z) gave every image its expected verdict (3 fixed, 4 still_affected,
      1 unknown for the credential-protected registry), and an over-stated fix claim gave
      `unknown` (the methods disagree). All six jobs passed.
- [x] Scope review of the M2 diff (2026-10-02): in scope; `verdict.not_assessed` (no M2 caller)
      removed and parked for M4; four interface details recorded as ADR-0007 Amendment 1.
- [x] Spec-source review of the M2 diff (2026-10-02): 19 gaps (17 missing citations, 2
      unverified), all closed in SPEC_NOTES §5, §9, §12, §17 and §18.
- [x] ADR-0007 Amendment 1 approved by the owner (2026-10-02); the `verify-summary` schema and
      example built.
- [x] CI green on the M2 closing push (2026-10-02): run 37006601557 on `f2f90b3`, all six jobs
      passed (5 commits checked, 363 unit tests, 2 integration tests with real Syft and Grype,
      8 example files valid, no leaks, no known vulnerabilities). **M2 closed.**
- [x] Remove the "no integration tests yet" exit-5 allowance from `make integration`.

## Live checks (owner request, 2026-10-02; ADR-0008)

Real public images, real Syft and Grype, the Grype DB as published that day.
- [x] Live suite (`tests/live/`, `make live`) passes against Docker Hub: certbot v2.6.0, v2.7.0
      and v5.8.0 for CVE-2023-32681; debian:12.0-slim and python:3.12-slim-bookworm for
      CVE-2023-4911 (KEV). First run 2026-10-02 on this machine (Syft 1.54.0, Grype 0.119.0, DB
      v6.1.9 built 2026-10-02T06:31:53Z): 2 passed in 193 s. Verdicts: certbot v2.6.0
      still_affected (requests 2.28.2, both methods); v2.7.0 fixed (2.31.0); v5.8.0 fixed
      (2.34.2); debian 12.0 still_affected (Grype matched libc6 and libc-bin 2.36-9; no Debian
      comparator yet); python:3.12-slim-bookworm unknown (no match, no comparator).
- [x] Weekly workflow `.github/workflows/live.yml` green on its first run (manual dispatch,
      2026-10-02): run 37009932265 on `ae7ea86`, 2 passed in 58 s on GitHub's runner (Syft
      1.54.0, Grype 0.119.0, DB v6.1.9 built 2026-10-02T06:31:53Z). The push's CI run
      37009910036 was green on all six jobs, including the integration job on the shared
      scanner install.

## M3 (week 5)

Version comparators for dpkg, rpm, apk, PyPI, npm and Maven with spec-derived test tables
(PyPI is built in M2, ADR-0007 Q2; its table is completed here).
- [x] Done: each comparator passes its table, including epochs and pre-releases (2026-10-02):
      `tests/test_version_{dpkg,rpm,apk,npm,maven}.py` plus `test_versions.py` (PyPI), with
      epochs (dpkg, rpm, PyPI) and pre-releases (`~`, `^`, `_alpha` to `_rc`, SemVer, Maven
      qualifiers). Dev-time agreement with each upstream: python-debian on 6,000+ seeded pairs;
      rpm's 91 active vectors; apk-tools' 709 applicable lines (60 grey-zone lines refused);
      node-semver's strict fixtures; every vector in Maven's own test class (SPEC_NOTES §6 to §11).
- [x] OQ-4 (dpkg and the GPL) answered (2026-10-02: (b), own comparator, `python-debian` only as
      a dev-only oracle).
- [x] The UNVERIFIED items in SPEC_NOTES §8, §10 and §11 resolved (2026-10-02).
- [x] Live data (ADR-0008 item 5), passed here 2026-10-02: CVE-2023-4911 (KEV) on Debian 12.0
      still_affected and python:3.12-slim-bookworm now `fixed` (libc6 2.36-9+deb12u14);
      CVE-2023-5363 on alpine:3.18.0 still_affected (3.1.0-r4) and alpine:3.22 fixed (3.5.8-r0);
      CVE-2023-0286 on almalinux:9.0 still_affected (1:3.0.1-43.el9_0) and almalinux:9 fixed
      (1:3.5.5-6.el9_8); CVE-2021-44228 (KEV) in a Spring Boot jar still_affected (log4j-core
      2.14.1; ADR-0008 Amendment 1).
- [x] The full live suite green on GitHub: live run 37014662509 on `a834f51` (5 tests, 10 real
      images); CI run 37017378838 on `e90d574` green on all six jobs.
- [x] Spec-source review of the M3 diff done and its 13 gaps closed (`b2f5f6a`); scope review
      done (its one finding became ADR-0008 Amendment 1). **M3 closed 2026-10-03.**

## M4 (weeks 6-7)

Kubernetes inventory on kind; pod to digest mapping; verdict per workload.
- [x] Done: SUCCESS TEST step 1 passes (2 `fixed`, 3 `still_affected` with image digests and
      pod names, 1 `unknown` with the reason). CI run 37110967647 passed, but run 37112442952
      failed (3 / 3 / 0): the password-protected demo image shared its digest with an open one,
      and the node named the open registry in `imageID` (SPEC_NOTES §12), so the first pass
      depended on pull order. Fixed in ad0bc59 (own digest, and the build fails on a shared
      one); CI 37112944135 green, 6 passed, and its demo step printed 2 / 3 / 1 (README).
- [x] OQ-5 (the unreadable workload) answered 2026-10-03: (a), an image in a registry fixproof
      has no credentials for.
- [x] `imageID` format verified (SPEC_NOTES §12, 2026-10-03, from the kubelet and containerd
      source).
- [x] M4 design accepted: ADR-0010 (owner approved 2026-10-03).
- [x] `kubernetes` dependency; `WorkloadAsset.owner`; bundle and verify-summary 1.1.0
      (367d534, bd2a951, a0b408a).
- [x] Inventory (`fixproof.inventory`) with unit tests on a fake Kubernetes API (bd2a951).
- [x] `verify` handles clusters: per-workload verdicts, each image scanned once, pod names in
      the output (a0b408a; unit tests on a fake cluster).
- [x] kind setup script and the CI integration job for the 6 success-test workloads
      (`scripts/demo_cluster.sh`, `tests/integration/test_cluster.py`, 78cffd9, ad0bc59); green
      in CI 37112944135.
- [ ] Read-only Role and RoleBinding YAML shipped (`deploy/kubernetes/`, 78cffd9), with a unit
      test that every inventory API call is granted; applied in CI 37110967647 (`can-i` showed get
      and list on pods and replicasets only; `403` for kube-system). Waiting on the owner to
      confirm ADR-0010 Amendment 1 (two files, the Namespace object, the kubectl pin).
- [x] Live data (ADR-0008 item 5): the kind cluster runs workloads from real public images, not
      only fixture images: namespace `fixproof-live` runs certbot v2.6.0 (`still_affected`) and
      v2.7.0 (`fixed`), both as expected in CI 37110967647.
- [x] Scope and spec reviews (2026-10-03). Fixed: pods with no container status yet were dropped
      (ab0d024); the client could write refreshed tokens back to the kubeconfig and read
      `KUBECONFIG` only at import (41041e9); 21 undocumented Kubernetes facts verified and
      recorded in SPEC_NOTES §12; README, CI comment, Makefile and PARKED brought up to date.

## M5 (week 8)

CI gate, KEV enrichment, HTML report, CycloneDX VEX.
- [ ] Done: SUCCESS TEST steps 2 and 3 pass (OpenVEX validates against the pinned schema with no
      `not_affected` without evidence; `fixproof gate` exits non-zero on a reintroduced closed
      CVE and zero otherwise).
- [x] OQ-3 (CycloneDX version) answered 2026-10-03: stay on 1.6 (patch 1.6.2).
- [ ] Live data (ADR-0008 item 5): KEV enrichment checked against the live CISA feed in the live
      suite.

## M6 (weeks 9-10)

Packaging, docs, demo, hardening only.
- [ ] Done: `make demo` runs the SUCCESS TEST end to end; docs match the CLI.
- [x] README with diagrams, a live demo and a user guide (owner request, 2026-10-02; written
      early, to be kept true as M4 to M6 land).
- [ ] Add the CI `release` job (tag `v*`: build, SBOM, PyPI trusted publishing), only after M6.

## Last session (resume here)

- **Date:** 2026-10-03. **Current milestone:** M4; done-criterion met; ready to close.
- **`main` = c230151, green:** work branch `m4-close` proved it first (dispatched CI 37115772416,
  all six jobs, integration 6 passed, demo 2 / 3 / 1), then `main` CI 37116173157, all six jobs
  green. The branch was deleted after. Integration is now green three runs in a row since the
  demo-digest fix (ad0bc59).
- **Owner rule (2026-10-03): `main` must never go red.** Changes that can affect the integration
  or live jobs are proven green on a work branch (`gh workflow run ci.yml --ref <branch>`)
  before `main` moves.
- **Committed locally, not pushed:** this resume block.
- **Waiting on the owner:** (1) confirm ADR-0010 Amendment 1 (RBAC as two files, the `fixproof`
  Namespace object, the kubectl pin); (2) close M4.
- **Next steps, in order:** on the owner's word, tick the RBAC item, record M4 closed, push
  through a work branch; then M5 (gate, KEV, HTML, CycloneDX 1.6).
