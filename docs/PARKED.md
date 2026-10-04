# Parked

Good ideas that are out of scope right now. Each entry: date, where it came from, and why it
waits.

- **2026-10-02, V2 plan:** hosts and VMs via SSH package queries; cloud asset inventories;
  non-destructive exploitability checks behind an explicit authorisation file; ticket sync; CRA
  final-report evidence export. Not built during the MVP.
- **2026-10-02, M0 setup: run gitleaks in `make check`.** It runs in CI only, because gitleaks is
  not installed locally. It could be added once gitleaks is installed.
- **2026-10-02, M0 setup: `uv audit`.** uv 0.12.9 has `uv audit`, which could replace pip-audit and
  its dependencies. pip-audit is the planned tool, so this waits for an owner decision.
- **2026-10-02, M0 research: CycloneDX 1.7 output.** 1.7.2 is the latest CycloneDX release; the
  plan pins 1.6 (OQ-3). Revisit after M5 if a consumer needs 1.7.
- **2026-10-02, M2 scope review: `unknown` for assets the methods never ran on.** M4 needs a
  verdict for a pod whose image digest is unresolved or whose registry is outside the allowlist
  (the methods cannot run, so the verdict is `unknown` with the reason). M2 has no such caller,
  so the helper was removed; it returns with the M4 inventory. **Resolved in M4** (a0b408a): `verify` gives such a
  workload `unknown` with the reason.
- **2026-10-03, M4 build: the platform a pod actually runs.** For a multi-platform image the
  kubelet reports the index digest, and Syft and Grype scan the platform of the machine running
  fixproof (recorded in the bundle's `scanned`). A pod on an arm64 node running an amd64-scanned
  index is therefore checked on the wrong platform. Reading the node's architecture needs `get`
  on nodes, a cluster-wide permission ADR-0010 does not grant; revisit if mixed-architecture
  clusters matter. **Resolved in M7** (ADR-0014): every platform of an index is checked, with
  no new permission.
- **2026-10-03, M4 build: a cluster where no workload resolves.** If every workload in scope
  has no image digest (all pending), there is no product for an OpenVEX statement, the schema
  needs at least one, and `verify` exits 3. Exit 2 with no VEX file would be more accurate;
  it waits because it changes the bundle layout (ADR-0007 item 7).
- **2026-10-03, M4 CI run 37112442952: show the pod spec's image next to `imageID`.** When a
  node holds one digest under two registries, `imageID` may name the other registry than the
  pod spec. The verdict is unaffected (same digest), but showing the spec's image too would
  explain the difference. It is a new output field, so it waits for an owner decision.
- **2026-10-03, M4 value test: scan distinct images in parallel.** Each distinct image is scanned
  once but one after another, so clusters with many images are slow. A new feature; waits for an
  owner decision. **Resolved 2026-10-03** (ADR-0011): `verify --jobs`, default 4.
- **2026-10-03, M4 value test: managed clusters and cloud registries.** EKS, GKE and AKS (with
  their exec credential plugins) and cloud registry credential helpers (ECR, Artifact Registry,
  ACR) are untested. Needs a cloud test account from the owner. **Partly resolved in M7**
  (ADR-0015): exec plugins and credential helpers are proven on kind; each cloud's own plugin
  and identity mapping still needs that account.
- **2026-10-03, M4 final spec review: CRI-O nodes.** minikube offers `--container-runtime=cri-o`;
  CRI-O's image ID form is not verified and not tested. The same CI pattern as the Docker
  Engine job would prove it; waits for an owner decision. **Resolved 2026-10-03** (ADR-0011): proven on a real
  CRI-O 1.35.7 node in CI.
- **2026-10-04, M5 scope review: a KEV cache or local mirror for air-gapped CI.** ADR-0012
  downloads the feed on every run; offline runs record `unavailable`. Waits for an owner decision.
- **2026-10-04, M5 scope review: an evidence bundle for `gate` decisions.** Today `gate` prints
  its result or `--json`; a bundle like `verify`'s would keep the raw tool output too.
  **Resolved in M7** (ADR-0016): `gate --out`.
- **2026-10-04, M5 scope review: more `gate` sources** (`podman:`, `oci-dir:`), refused today.
