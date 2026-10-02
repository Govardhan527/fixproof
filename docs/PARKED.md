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
