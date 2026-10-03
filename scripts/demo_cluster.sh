#!/usr/bin/env bash
# The demo cluster (ADR-0010 item 9): two local registries (one open, one that needs a password),
# the fixture images, a kind cluster that pulls from both, the demo workloads in three namespaces
# (scripts/demo_workloads.py), and a kubeconfig for fixproof's read-only account. The CI
# `integration` job runs it; `make demo` will in M6.
#   scripts/demo_cluster.sh up WORKDIR      needs Docker, curl, openssl and uv
#   scripts/demo_cluster.sh down WORKDIR
# WORKDIR receives bin/ (kind and kubectl, checksum-verified), fixture-images.json,
# admin.kubeconfig and reader.kubeconfig. Your own Docker and kubectl configs are not touched.
set -euo pipefail

CLUSTER=fixproof
CONTEXT="kind-$CLUSTER"
KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KUBECTL_VERSION=v1.37.1
KUBECTL_SHA256=65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8
NODE_IMAGE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
REGISTRY_IMAGE=registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
HTPASSWD_IMAGE=httpd@sha256:4e585da9d0125dec36d4500a9f5c5df7b2c0a01f67cb47865a91a4b05bdbec1b
OPEN_REGISTRY=fixproof-registry OPEN_PORT=5001
AUTH_REGISTRY=fixproof-auth-registry AUTH_PORT=5002
PULL_SECRET=auth-registry
NAMESPACES=(fixproof-demo fixproof-live fixproof-edge)  # as in scripts/demo_workloads.py
SIDE_LOADED=fixproof-side-loaded:it  # demo_workloads.SIDE_LOADED

repo="$(cd "$(dirname "$0")/.." && pwd)"
command="${1:?usage: demo_cluster.sh up|down WORKDIR}"
work="${2:?usage: demo_cluster.sh up|down WORKDIR}"
mkdir -p "$work/bin"
work="$(cd "$work" && pwd)"
export PATH="$work/bin:$PATH"

install_tools() {
    if [[ ! -x "$work/bin/kind" ]]; then
        curl -sSfL -o "$work/bin/kind.download" \
            "https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-linux-amd64"
        echo "$KIND_SHA256  $work/bin/kind.download" | sha256sum --check --strict
        chmod +x "$work/bin/kind.download" && mv "$work/bin/kind.download" "$work/bin/kind"
    fi
    if [[ ! -x "$work/bin/kubectl" ]]; then
        curl -sSfL -o "$work/bin/kubectl.download" \
            "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
        echo "$KUBECTL_SHA256  $work/bin/kubectl.download" | sha256sum --check --strict
        chmod +x "$work/bin/kubectl.download" && mv "$work/bin/kubectl.download" "$work/bin/kubectl"
    fi
    kind version
    kubectl version --client
}

wait_for() {  # wait_for PORT: until the registry answers (401 counts: it is up)
    for _ in $(seq 30); do
        curl -s -o /dev/null "http://localhost:$1/v2/" && return 0
        sleep 1
    done
    echo "registry on port $1 did not start" >&2
    return 1
}

start_registries() {
    password="$(openssl rand -hex 24)"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::add-mask::$password"; fi
    mkdir -p "$work/auth"
    docker run --rm --entrypoint htpasswd "$HTPASSWD_IMAGE" -Bbn fixproof "$password" \
        > "$work/auth/htpasswd"
    docker run -d --restart=always --name "$OPEN_REGISTRY" -p "127.0.0.1:$OPEN_PORT:5000" \
        "$REGISTRY_IMAGE" > /dev/null
    docker run -d --restart=always --name "$AUTH_REGISTRY" -p "127.0.0.1:$AUTH_PORT:5000" \
        -v "$work/auth:/auth:ro" -e REGISTRY_AUTH=htpasswd -e REGISTRY_AUTH_HTPASSWD_REALM=fixproof \
        -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd "$REGISTRY_IMAGE" > /dev/null
    wait_for "$OPEN_PORT"
    wait_for "$AUTH_PORT"
}

push_fixtures() {  # the push credentials live in WORKDIR/docker only
    echo "$password" | DOCKER_CONFIG="$work/docker" docker login "localhost:$AUTH_PORT" \
        --username fixproof --password-stdin
    DOCKER_CONFIG="$work/docker" uv run --frozen python "$repo/scripts/build_fixtures.py" \
        --registry "localhost:$OPEN_PORT" --auth-registry "localhost:$AUTH_PORT" \
        --out "$work/fixture-images.json"
}

create_cluster() {
    kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" \
        --kubeconfig "$work/admin.kubeconfig" --wait 180s
    # localhost in a node is not the host: send each registry port to its container
    # (kind node images from v0.27.0 already read /etc/containerd/certs.d; SPEC_NOTES §12)
    for node in $(kind get nodes --name "$CLUSTER"); do
        for pair in "$OPEN_PORT:$OPEN_REGISTRY" "$AUTH_PORT:$AUTH_REGISTRY"; do
            dir="/etc/containerd/certs.d/localhost:${pair%%:*}"
            docker exec "$node" mkdir -p "$dir"
            printf '[host."http://%s:5000"]\n' "${pair#*:}" \
                | docker exec -i "$node" cp /dev/stdin "$dir/hosts.toml"
        done
    done
    for registry in "$OPEN_REGISTRY" "$AUTH_REGISTRY"; do
        if [[ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "$registry")" == null ]]; then
            docker network connect kind "$registry"
        fi
    done
}

deploy() {
    local admin=(kubectl --kubeconfig "$work/admin.kubeconfig")
    "${admin[@]}" apply -f "$repo/deploy/kubernetes/fixproof-reader.yaml"
    for namespace in "${NAMESPACES[@]}"; do
        "${admin[@]}" create namespace "$namespace"
        "${admin[@]}" apply -n "$namespace" -f "$repo/deploy/kubernetes/fixproof-reader-role.yaml"
    done
    "${admin[@]}" create secret docker-registry "$PULL_SECRET" -n fixproof-demo \
        --docker-server="localhost:$AUTH_PORT" --docker-username=fixproof \
        --docker-password="$password" > /dev/null
    uv run --frozen python "$repo/scripts/demo_workloads.py" \
        --images "$work/fixture-images.json" --pull-secret "$PULL_SECRET" \
        | "${admin[@]}" apply -f -
    for namespace in fixproof-demo fixproof-live; do
        "${admin[@]}" wait --for=condition=Available deployment --all -n "$namespace" \
            --timeout=600s
    done
    wait_for_edge_cases
    "${admin[@]}" get pods -A -o wide
}

side_load() {  # built here and copied into the node; the node names it docker.io/library/import-<date>
    docker build --quiet --label fixproof.fixture.loaded=kind --tag "$SIDE_LOADED" \
        "$repo/tests/fixtures/images/requests-2.31.0" > /dev/null
    kind load docker-image "$SIDE_LOADED" --name "$CLUSTER"
}

wait_for_edge_cases() {  # each fixproof-edge workload in the state its test expects
    local edge=(kubectl --kubeconfig "$work/admin.kubeconfig" -n fixproof-edge)
    local debug_image
    "${edge[@]}" wait --for=condition=Available deployment/two-replicas deployment/side-loaded \
        deployment/by-tag \
        --timeout=600s
    "${edge[@]}" wait --for=condition=Ready pod/bare-pod --timeout=600s
    "${edge[@]}" wait --for=condition=PodScheduled=false pod \
        -l app.kubernetes.io/name=unschedulable --timeout=300s
    "${edge[@]}" wait --for=jsonpath='{.status.containerStatuses[0].state.waiting.reason}'=ImagePullBackOff \
        pod -l app.kubernetes.io/name=pull-backoff --timeout=300s
    # An ephemeral debug container, which fixproof must skip (ADR-0010 item 1)
    debug_image="$(uv run --frozen python -c \
        'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
        "$work/fixture-images.json" requests-2.25.1)"  # demo_workloads.DEBUG_FIXTURE
    "${edge[@]}" debug pod/bare-pod --image="$debug_image" --container=debugger -- sleep 86400
    "${edge[@]}" wait --for=jsonpath='{.status.ephemeralContainerStatuses[0].state.running}' \
        pod/bare-pod --timeout=300s
}

reader_kubeconfig() {  # fixproof's view: a 2-hour token for fixproof-reader, nothing else
    "$repo/scripts/reader_kubeconfig.sh" "$work/admin.kubeconfig" "$work/reader.kubeconfig" \
        "$CONTEXT" fixproof-demo
}

case "$command" in
    up)
        install_tools
        start_registries
        push_fixtures
        create_cluster
        side_load
        deploy
        reader_kubeconfig
        echo "demo cluster ready: KUBECONFIG=$work/reader.kubeconfig, context $CONTEXT"
        ;;
    down)
        if [[ -x "$work/bin/kind" ]]; then kind delete cluster --name "$CLUSTER"; fi
        docker rm -f "$OPEN_REGISTRY" "$AUTH_REGISTRY" > /dev/null 2>&1 || true
        ;;
    *)
        echo "usage: demo_cluster.sh up|down WORKDIR" >&2
        exit 2
        ;;
esac
