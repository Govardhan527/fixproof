#!/usr/bin/env bash
# Upload a release to PyPI (ADR-0013 Amendment 2). Takes the wheel and sdist that the release
# workflow built and attached to the GitHub release for TAG, checks them against that release's
# SHA256SUMS and with `twine check --strict`, then uploads exactly those files with twine and the
# credentials in ~/.pypirc. A pre-release is checked and never uploaded. An upload cannot be
# undone, and running it is the owner's step.
#   scripts/publish.sh vX.Y.Z
set -euo pipefail

repo="Govardhan527/fixproof"
tag="${1:?usage: publish.sh vX.Y.Z}"
version="${tag#v}"
[[ "$tag" == "v$version" && -n "$version" ]] || { echo "not a version tag: $tag" >&2; exit 1; }
packages=("fixproof-$version-py3-none-any.whl" "fixproof-$version.tar.gz")
twine=(uvx --from twine==7.0.0 twine)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
prerelease="$(gh release view "$tag" --repo "$repo" --json isPrerelease --jq .isPrerelease)"
gh release download "$tag" --repo "$repo" --dir "$work" \
  --pattern SHA256SUMS --pattern "${packages[0]}" --pattern "${packages[1]}"
cd "$work"

# The sums must name these two files and nothing else, so nothing unchecked is uploaded
listed="$(awk '{ sub(/^\*?\.\//, "", $2); print $2 }' SHA256SUMS | sort | paste -sd ' ')"
wanted="$(printf '%s\n' "${packages[@]}" | sort | paste -sd ' ')"
[[ "$listed" == "$wanted" ]] || {
  echo "SHA256SUMS lists '$listed', expected '$wanted'" >&2; exit 1; }
sha256sum --check --strict SHA256SUMS
"${twine[@]}" check --strict "${packages[@]}"

if [[ "$prerelease" != "false" ]]; then
  echo "$tag is a pre-release: its packages are checked and not uploaded"
  exit 0
fi
"${twine[@]}" upload --non-interactive "${packages[@]}"
echo "uploaded ${packages[*]} to PyPI"
