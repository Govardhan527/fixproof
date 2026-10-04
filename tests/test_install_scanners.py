"""The scanner install script installs exactly the pinned tools recorded in SPEC_NOTES.

Syft and Grype (ADR-0002 item 7, SPEC_NOTES §12) and crane (ADR-0014, SPEC_NOTES §20): each
download is checked against a SHA-256, and every version and SHA-256 the script uses must be the
one SPEC_NOTES records, so a pin cannot change in one place only.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scripts" / "install_scanners.sh").read_text(encoding="utf-8")
NOTES = (ROOT / "docs" / "SPEC_NOTES.md").read_text(encoding="utf-8")


def test_syft_and_grype_are_pinned_as_recorded() -> None:
    found = re.findall(r"^fetch (\w+) ([0-9.]+) ([a-f0-9]{64})$", SCRIPT, re.M)
    pins = {name: (version, sha) for name, version, sha in found}
    assert set(pins) == {"syft", "grype"}
    for name, (version, sha) in pins.items():
        assert sha in NOTES, f"{name}'s SHA-256 is not in SPEC_NOTES"
        assert version in NOTES, f"{name} {version} is not in SPEC_NOTES"


def test_crane_is_pinned_as_recorded_and_checked_before_unpacking() -> None:
    (version,) = set(re.findall(r"go-containerregistry/releases/download/v([0-9.]+)/", SCRIPT))
    (sha,) = re.findall(r'echo "([a-f0-9]{64})  \$tmp/\$crane_archive"', SCRIPT)
    assert f"go-containerregistry` v{version}" in NOTES
    assert sha in NOTES, "crane's SHA-256 is not in SPEC_NOTES §20"
    check = SCRIPT.index("sha256sum --check --strict", SCRIPT.index("crane_archive="))
    assert check < SCRIPT.index('-C "$dest" crane'), "crane must be checked before it is unpacked"
    assert 'tar -xzf "$tmp/$crane_archive" -C "$dest" crane\n' in SCRIPT  # crane only
