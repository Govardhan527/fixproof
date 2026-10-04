#!/usr/bin/env bash
# make demo: the SUCCESS TEST, end to end, on a local kind cluster (ADR-0013 item 1).
#   scripts/demo.sh up      install the pinned scanners, update the Grype DB, start the demo
#                           cluster (or reuse it) and run scripts/success_test.py
#   scripts/demo.sh down    remove the demo cluster and its registries
# Needs Docker, curl, openssl and uv. Everything goes under .demo/ (or $FIXPROOF_DEMO_DIR) except
# the Grype DB, which goes to Grype's own cache (about 3 GB), so later runs reuse it.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="${FIXPROOF_DEMO_DIR:-$repo/.demo}"
command="${1:-up}"

case "$command" in
    up)
        mkdir -p "$work/bin"
        if [[ ! -x "$work/bin/syft" || ! -x "$work/bin/grype" ]]; then
            "$repo/scripts/install_scanners.sh" "$work/bin"
        fi
        export PATH="$work/bin:$PATH"
        GRYPE_CHECK_FOR_APP_UPDATE=false grype db update
        if [[ -f "$work/reader.kubeconfig" ]] \
            && "$work/bin/kind" get clusters 2> /dev/null | grep -qx fixproof; then
            echo "reusing the demo cluster in $work (make demo-down removes it)"
        else
            "$repo/scripts/demo_cluster.sh" up "$work"
        fi
        uv run --frozen python "$repo/scripts/success_test.py" --work "$work"
        ;;
    down)
        "$repo/scripts/demo_cluster.sh" down "$work"
        ;;
    *)
        echo "usage: demo.sh up|down" >&2
        exit 2
        ;;
esac
