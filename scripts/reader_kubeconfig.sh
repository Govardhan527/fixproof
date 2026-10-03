#!/usr/bin/env bash
# A kubeconfig holding only a short-lived token for fixproof's read-only account, made the way
# the README tells users to (deploy/kubernetes/, ADR-0010 item 7). kubectl must be on PATH.
#   scripts/reader_kubeconfig.sh ADMIN_KUBECONFIG OUT CONTEXT [NAMESPACE]
# NAMESPACE, if given, has its permissions listed afterwards. The token is never printed, and is
# masked in GitHub Actions logs.
set -euo pipefail

admin_config="${1:?usage: reader_kubeconfig.sh ADMIN_KUBECONFIG OUT CONTEXT [NAMESPACE]}"
out="${2:?usage: reader_kubeconfig.sh ADMIN_KUBECONFIG OUT CONTEXT [NAMESPACE]}"
context="${3:?usage: reader_kubeconfig.sh ADMIN_KUBECONFIG OUT CONTEXT [NAMESPACE]}"
namespace="${4:-}"
admin=(kubectl --kubeconfig "$admin_config")
reader=(kubectl --kubeconfig "$out")
ca="$(dirname "$out")/ca.crt"

token="$("${admin[@]}" create token fixproof-reader -n fixproof --duration=2h)"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::add-mask::$token"; fi
server="$("${admin[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
# --flatten embeds a CA given as a file path (minikube) as well as one given as data (kind)
"${admin[@]}" config view --raw --minify --flatten \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$ca"
rm -f "$out"
"${reader[@]}" config set-cluster "$context" --server="$server" \
    --certificate-authority="$ca" --embed-certs=true > /dev/null
"${reader[@]}" config set-credentials fixproof-reader --token="$token" > /dev/null
"${reader[@]}" config set-context "$context" --cluster="$context" --user=fixproof-reader > /dev/null
"${reader[@]}" config use-context "$context" > /dev/null
chmod 600 "$out"
if [[ -n "$namespace" ]]; then "${reader[@]}" auth can-i --list -n "$namespace"; fi
