#!/usr/bin/env bash
# Install the pinned Syft and Grype release binaries into DIR, checking each archive against the
# SHA-256 recorded from its release's checksums file (ADR-0002 item 7, SPEC_NOTES §12).
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
"$dest/syft" version
"$dest/grype" version
