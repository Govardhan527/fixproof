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
- [x] Read-only Role and RoleBinding YAML shipped (`deploy/kubernetes/`, 78cffd9), with a unit
      test that every inventory API call is granted; applied on both CI clusters, with a
      `kubectl auth can-i` matrix and `403` outside its namespaces. ADR-0010 Amendment 1 (two
      files, the Namespace object, the kubectl pin) confirmed by the owner 2026-10-03.
- [x] Live data (ADR-0008 item 5): the kind cluster runs workloads from real public images, not
      only fixture images: namespace `fixproof-live` runs certbot v2.6.0 (`still_affected`) and
      v2.7.0 (`fixed`), both as expected in CI 37110967647.
- [x] Every ADR-0010 case tested on the real cluster, not only on fakes (owner, 2026-10-03:
      no test may be missing): namespace `fixproof-edge` (init container, a native sidecar
      added at the M4 close, two containers per pod, two replicas sharing evidence, bare pod, ephemeral container skipped, pull failure, unscheduled pod,
      side-loaded image), images and clusters in one scope, two namespaces with one token, a
      registry outside the allowlist, a `kubectl auth can-i` matrix for the reader, pods by tag
      and by Docker Hub short name, a private registry with credentials (none leak into the
      output), and the CI demo run with fixproof installed with the README's command. Branch run
      37117704337 showed the node names a side-loaded image `docker.io/library/import-<date>`
      (SPEC_NOTES corrected); branch run 37118476594: 34 passed.
- [x] Docker Engine nodes (ADR-0010 Amendment 2, owner approved 2026-10-03): cri-dockerd image
      IDs read and Docker's short names expanded (e9ee0dd); proven on a real minikube node with
      Docker Engine 29.7.2 by the CI job `integration-docker-runtime` (8f33458), branch run
      37123230999: 3 passed; `main` CI 37124348833 green with both cluster jobs. (Earlier notes
      said Docker Engine is minikube's default; minikube's default is containerd, corrected.)
- [x] Scope and spec reviews (2026-10-03). Fixed: pods with no container status yet were dropped
      (ab0d024); the client could write refreshed tokens back to the kubeconfig and read
      `KUBECONFIG` only at import (41041e9); 21 undocumented Kubernetes facts verified and
      recorded in SPEC_NOTES §12; README, CI comment, Makefile and PARKED brought up to date.
- [x] Final spec and scope reviews of `d7ff7cd..f2da9da` (2026-10-03): no out-of-scope work.
      Fixed: a wrong claim that Docker Engine is minikube's default; the README's kubeconfig
      steps lacked `--flatten` (needed on minikube); a test that the Kubernetes token never
      appears in output; denied subresources checked against the API server's discovery; a real
      native sidecar in `fixproof-edge`; the raw Docker short-name image IDs asserted; CI installs
      with the README's own `git+https://` command and asserts the printed counts; SPEC_NOTES
      gained the OBSERVED tag and every fact the review found missing; three gaps parked (parallel scans, managed
      clusters and cloud registries, CRI-O). **M4 closed 2026-10-03** (owner: "confirm and close
      M4").

### Value test for M4: what a real user can and cannot rely on yet (2026-10-03)

The owner's test: could a user run this today, on their own clusters and images, following only
the README, and act on the answer?
- Can, with CI evidence: install with the README's `uv tool install git+https://…` command (the
  CI demo steps run exactly that, pinned to the commit under test), point fixproof at a namespace
  with the shipped read-only account, on a containerd node (kind), a Docker Engine node or a
  CRI-O node (minikube), get a verdict per pod with pod name, scanning several images at once,
  owner and digest, for images referenced by tag, short name or digest, from Docker Hub or a
  private registry, with or without registry credentials, and keep evidence that holds neither
  the registry password nor the Kubernetes token.
- Cannot yet rely on:
  - Managed clusters (EKS, GKE, AKS) are untested. The reader token works on any conformant API
    server, but a user's own context with an exec credential plugin has not been tried.
  - Cloud registry credential helpers (ECR, Artifact Registry, ACR) are untested; only a
    user-and-password Docker config is.
  - Pods on arm64 nodes (PARKED: the node's platform is not checked).
  - fixproof is not on PyPI (M6).
  Each needs an owner decision (a cloud account to test against, or M6 scope).

## After M4: owner additions (ADR-0011, 2026-10-03)

- [x] `verify --jobs N` (default 4): distinct images scanned several at a time; identical evidence
      for any N; overlap proven by a barrier test (b45a770).
- [x] CRI-O nodes proven on a real minikube node with CRI-O 1.35.7: the minikube CI job is a
      matrix over Docker Engine and CRI-O (11864f6). The node reported the `linux/amd64`
      manifest for one multi-platform image; the test accepts it only as Docker Hub lists it
      (f965004). Branch run 37134011580: kind 35, Docker Engine 4, CRI-O 4 passed.

## M5 (week 8)

CI gate, KEV enrichment, HTML report, CycloneDX VEX.
- [x] Done: SUCCESS TEST steps 2 and 3 pass (OpenVEX validates against the pinned schema with no
      `not_affected` without evidence; `fixproof gate` exits non-zero on a reintroduced closed
      CVE and zero otherwise). Evidence: branch CI 37137847475 and 37138302512 (kind job: 41
      integration tests, among them the 6 real-image gate tests; every bundle's OpenVEX and
      CycloneDX validated, statuses exact).
- [x] OQ-3 (CycloneDX version) answered 2026-10-03: stay on 1.6 (patch 1.6.2).
- [x] Facts verified (SPEC_NOTES §3, §4, §12, 2026-10-03): the live KEV feed and its schema; the
      CycloneDX 1.6.2 state definitions, its two companion schemas and offline validation of
      `cyclonedx-python-lib` 11.12.0 output; the pinned tools' image source schemes.
- [x] M5 design accepted: ADR-0012 (owner answered the four questions 2026-10-03).
- [x] KEV enrichment: fetched on every run, validated, recorded; `unavailable` never changes a
      verdict; `bundle` and `verify-summary` 1.2.0 (19aa0d4). The live KEV test passed locally
      against the real feed (2026-10-03).
- [x] CycloneDX 1.6 VEX (`cyclonedx.json`) validated against the official schema; golden file
      (2061608). Owner approved exempting `src/fixproof/schemas/official/` (pinned third-party
      schemas) from the commit word check, as the official schema's own text trips it.
- [x] HTML summary (`report.html`), self-contained; golden file (263314c).
- [x] `closed.yaml` and `fixproof gate` (exit 0 / 1 / 2 / 3, `gate-result`), registry by digest
      and local builds (`docker:`, `docker-archive:`, `oci-archive:`) (df351e3). `oci-archive:`
      checked locally on a real alpine archive: both tools report its image ID and manifest
      digest.
- [x] Integration: the gate on real fixture images in CI (reintroduced, fixed, unreadable), from
      the Docker daemon, a `docker save` archive, an OCI archive and the registry (f716ff2);
      green in branch CI 37137847475 and 37138302512.
- [x] Live data (ADR-0008 item 5): KEV enrichment checked against the live CISA feed in the live
      suite (f716ff2): 6 passed locally and in the live job on the branch (37138305026).
- [x] M5 spec and scope reviews (2026-10-04): no out-of-scope work. Fixed: `gate` prints why KEV
      is unavailable and a test shows it changes no exit code; the integration evidence no
      longer depends on cisa.gov; SPEC_NOTES gained the CSP, OCI layout, registry API,
      CycloneDX field and serial-number, library and local-build facts; ADR-0012 Amendment 1
      records the details the build settled (confirmed by the owner 2026-10-04); three ideas
      parked. `main` = 6b09f36, CI 37164132919 green on all eight jobs. **M5 closed
      2026-10-04** (owner: "confirm and close M5").

## M6 (weeks 9-10)

Packaging, docs, demo, hardening only.
- [x] Done: `make demo` runs the SUCCESS TEST end to end; docs match the CLI. Evidence: branch
      CI 37165585399, job `demo` ran exactly `make demo` from a fresh runner: "SUCCESS TEST: PASS
      (3/3 steps)"; the README-to-CLI test passes in `make check`.
- [x] README with diagrams, a live demo and a user guide (owner request, 2026-10-02; written
      early, to be kept true as M4 to M6 land).
- [x] M6 design accepted: ADR-0013 (owner answered the four questions 2026-10-04).
- [x] Hardening: safe YAML inputs (1 MB, no anchors or aliases); Kubernetes API timeouts; tool
      output read up to 512 MB; property-based tests of the comparators and parsers (e7ad5c3,
      377f46a, bf9af2e, 82b41eb).
- [x] `make demo` (`scripts/demo.sh`, `scripts/success_test.py`) and the CI `demo` job (c4f03a7);
      green on its first CI run (37165585399).
- [x] A test that holds the README to the CLI (options, exit codes, make targets) (10fce03); it
      found the gate section had no options table or console example.
- [x] Version 0.1.0, package metadata, a CI check that the built wheel installs and runs
      (7d28898); green in CI 37165585399 (job `package`).
- [x] Add the CI `release` job (tag `v*`: build, SBOM, GitHub release), only after M6
      (ADR-0013 item 5, Amendments 1 and 2): `.github/workflows/release.yml` written (86428d3)
      and hardened after the reviews. On the owner's instruction (2026-10-04) PyPI upload is the
      owner's step with `scripts/publish.sh` and their `~/.pypirc`, not trusted publishing; the
      workflow no longer publishes. Rehearsal passed 2026-10-04: tag `v0.1.0rc1` on a5df745
      (`main` CI 37188148312 green), release run 37188611616 made the GitHub pre-release; its
      wheel, installed in a fresh environment with the scanners from `install_scanners.sh`,
      repeated the README live demo on the three Certbot images (`still_affected`, `fixed`,
      `fixed`, exit 1, 76 s, Grype DB v6.1.10), wrote valid OpenVEX and CycloneDX, and gated
      v2.6.0 with exit 1 and v5.8.0 with exit 0; `scripts/publish.sh v0.1.0rc1` checked the sums
      and `twine check` and stopped (pre-release). **Released 2026-10-04:** `main` = e874af4
      (branch runs 37189050957 and 37189592124, `main` CI 37190137341, all green); tag `v0.1.0`,
      release run 37190692017, GitHub release "fixproof 0.1.0" (Latest) with the wheel, sdist,
      SBOM and `SHA256SUMS`; on the owner's "run it", `scripts/publish.sh v0.1.0` uploaded both
      files to https://pypi.org/project/fixproof/0.1.0/, and PyPI's sha256 for each equals
      `SHA256SUMS`. `uv tool install fixproof` and `pipx install fixproof` install 0.1.0 from
      PyPI in fresh environments; the uv install repeated the Certbot check (exit 1) and the gate
      (exit 1 on v2.6.0).
- [x] M6 spec and scope reviews (2026-10-04): nothing out of scope. Fixed: pre-releases detected
      with `packaging` (dev releases were missed); the release checks the commit is on a green
      `main`; README links absolute for the PyPI page; limits documented; test gaps closed (make
      targets both ways, purls of every type, the purl parser fuzzed, a real silent API server, an
      oversized output reaching `unknown`); `make demo-down` in CI; 18 release and packaging
      facts recorded. ADR-0013 Amendment 1 confirmed by the owner 2026-10-04. Second branch run
      37166399390 green, again "SUCCESS TEST: PASS (3/3 steps)".
- [x] Release spec and scope reviews (2026-10-04, `0ecd07b..e874af4`): nothing out of scope.
      Fixed: SPEC_NOTES §18 gained sourced entries for twine's defaults and what `twine check`
      checks, `uvx --from`, PyPI token scope and file-name reuse, wheel and sdist file names,
      `sha256sum`, `authors`, `jobs.<id>.needs`, `==`, YAML 1.1 booleans, gh output and the
      PyPI, pipx and tag URLs; the `check_package.sh` comment no longer claims more than
      `twine check` does; a stale TestPyPI comment in the release workflow corrected. **M6
      closed 2026-10-04** (owner: "Approved", to "confirm and close M6"). Every milestone of the
      project plan is done, and the SUCCESS TEST passes via `make demo` in CI on `main`.

## Last session (resume here)

- **Date:** 2026-10-04. **Current milestone:** none. M0 to M6 are closed (M6 on the owner's
  "Approved", 2026-10-04); the SUCCESS TEST passes via `make demo` in CI on `main`.
- **fixproof 0.1.0 is released:** https://pypi.org/project/fixproof/0.1.0/ and the GitHub release
  `v0.1.0` (Latest), the same bytes on both (sha256 checked); installs with `uv tool install
  fixproof` or `pipx install fixproof`. Details in the M6 release item.
- **Release route (ADR-0013 Amendment 2, confirmed):** bump the version on a branch, prove it in
  CI, move `main`, tag `vX.Y.Z` (the workflow makes the GitHub release), then the owner runs,
  or asks for, `scripts/publish.sh vX.Y.Z`; check the PyPI sha256 values against `SHA256SUMS`.
- **Last work:** the release review fixes and this record went through the work branch
  `m6-close` (two full green runs) to `main`; the run ids are in the M6 items above and in git.
- **Waiting on the owner:** what comes next. Candidates are in `docs/PARKED.md` (the plan's V2
  items, managed clusters and cloud credential helpers, arm64 nodes, a KEV cache for air-gapped
  use, a gate evidence bundle, more gate sources). Nothing is planned until the owner picks.
