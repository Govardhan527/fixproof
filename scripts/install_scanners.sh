#!/usr/bin/env bash
# Install the pinned Syft, Grype and crane release binaries into DIR, checking each archive
# against the SHA-256 recorded from its release's checksums file (ADR-0002 item 7, SPEC_NOTES §12;
# crane, which lists an image's platforms: ADR-0014, SPEC_NOTES §20).
#   scripts/install_scanners.sh DIR
set -euo pipefail

dest="${1:?usage: install_scanners.sh DIR}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
    local name="$1" version="$2" sha256="$3"
    local archive="${name}_${version}_linux_amd64.tar.gz"
    curl -sSfL -o "$tmp/$archive" \
        "https://github.com/anchore/${name}/releases/download/v${version}/${archive}"
    echo "${sha256}  $tmp/$archive" | sha256sum --check --strict
    tar -xzf "$tmp/$archive" -C "$dest" "$name"
}

mkdir -p "$dest"
fetch syft 1.54.0 54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860
fetch grype 0.119.0 3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b
# crane comes in go-containerregistry's release archive; only `crane` is extracted
crane_archive="go-containerregistry_Linux_x86_64.tar.gz"
curl -sSfL -o "$tmp/$crane_archive" \
    "https://github.com/google/go-containerregistry/releases/download/v0.22.1/$crane_archive"
echo "0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0  $tmp/$crane_archive" \
    | sha256sum --check --strict
tar -xzf "$tmp/$crane_archive" -C "$dest" crane
"$dest/syft" version
"$dest/grype" version
echo "crane $("$dest/crane" version)"
