#!/usr/bin/env bash
# A minikube node with a chosen container runtime: Docker Engine through cri-dockerd (ADR-0010
# Amendment 2) or CRI-O (ADR-0011). The kind demo covers containerd, also minikube's own default.
# It runs the minikube workloads (scripts/demo_workloads.py --minikube), images from Docker Hub
# written with Docker's short names and one image loaded into the node, and writes a kubeconfig
# for fixproof's read-only account. The CI `integration-minikube` jobs run it.
#   scripts/demo_minikube.sh up WORKDIR [docker|cri-o]      needs Docker, curl and uv
#   scripts/demo_minikube.sh down WORKDIR [docker|cri-o]
# WORKDIR receives bin/ (minikube and kubectl, checksum-verified), admin.kubeconfig and
# reader.kubeconfig. Your own kubectl config is not touched.
set -euo pipefail

LOCAL_IMAGE=localhost/fixproof-local:it  # demo_workloads.MINIKUBE_LOCAL
MINIKUBE_VERSION=v1.39.0
MINIKUBE_SHA256=b738496da01be06bbaf80c688f57ce25acd3849fbb518155f3a88e03ef555aa4
KUBERNETES_VERSION=v1.37.0  # minikube v1.39.0's default
KUBECTL_VERSION=v1.37.1
KUBECTL_SHA256=65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8

repo="$(cd "$(dirname "$0")/.." && pwd)"
command="${1:?usage: demo_minikube.sh up|down WORKDIR [docker|cri-o]}"
work="${2:?usage: demo_minikube.sh up|down WORKDIR [docker|cri-o]}"
RUNTIME="${3:-docker}"
case "$RUNTIME" in  # demo_workloads.MINIKUBE_NAMESPACES; the profile is the kubeconfig context
    docker) PROFILE=fixproof-docker ;;
    cri-o) PROFILE=fixproof-crio ;;
    *) echo "runtime must be docker or cri-o" >&2; exit 2 ;;
esac
NAMESPACE="$PROFILE"
mkdir -p "$work/bin"
work="$(cd "$work" && pwd)"
export PATH="$work/bin:$PATH"
export KUBECONFIG="$work/admin.kubeconfig"  # minikube writes its context here

install_tools() {
    if [[ ! -x "$work/bin/minikube" ]]; then
        curl -sSfL -o "$work/bin/minikube.download" \
            "https://github.com/kubernetes/minikube/releases/download/$MINIKUBE_VERSION/minikube-linux-amd64"
        echo "$MINIKUBE_SHA256  $work/bin/minikube.download" | sha256sum --check --strict
        chmod +x "$work/bin/minikube.download" && mv "$work/bin/minikube.download" "$work/bin/minikube"
    fi
    if [[ ! -x "$work/bin/kubectl" ]]; then
        curl -sSfL -o "$work/bin/kubectl.download" \
            "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
        echo "$KUBECTL_SHA256  $work/bin/kubectl.download" | sha256sum --check --strict
        chmod +x "$work/bin/kubectl.download" && mv "$work/bin/kubectl.download" "$work/bin/kubectl"
    fi
    minikube version
    kubectl version --client
}

start_node() {
    minikube start --profile "$PROFILE" --driver=docker --container-runtime="$RUNTIME" \
        --kubernetes-version="$KUBERNETES_VERSION" --wait=all
    kubectl get nodes -o wide  # CONTAINER-RUNTIME shows docker:// or cri-o://
}

load_local_image() {  # loaded into the node, never pulled from a registry
    docker build --quiet --label fixproof.fixture.loaded=minikube --tag "$LOCAL_IMAGE" \
        "$repo/tests/fixtures/images/requests-2.31.0" > /dev/null
    minikube --profile "$PROFILE" image load "$LOCAL_IMAGE"
}

deploy() {
    kubectl apply -f "$repo/deploy/kubernetes/fixproof-reader.yaml"
    kubectl create namespace "$NAMESPACE"
    kubectl apply -n "$NAMESPACE" -f "$repo/deploy/kubernetes/fixproof-reader-role.yaml"
    uv run --frozen python "$repo/scripts/demo_workloads.py" --minikube "$NAMESPACE" \
        | kubectl apply -f -
    kubectl wait --for=condition=Available deployment --all -n "$NAMESPACE" --timeout=600s
    kubectl get pods -n "$NAMESPACE" -o wide
}

case "$command" in
    up)
        install_tools
        start_node
        load_local_image
        deploy
        "$repo/scripts/reader_kubeconfig.sh" "$work/admin.kubeconfig" "$work/reader.kubeconfig" \
            "$PROFILE" "$NAMESPACE"
        echo "minikube node ready: KUBECONFIG=$work/reader.kubeconfig, context $PROFILE"
        ;;
    down)
        if [[ -x "$work/bin/minikube" ]]; then minikube delete --profile "$PROFILE"; fi
        ;;
    *)
        echo "usage: demo_minikube.sh up|down WORKDIR" >&2
        exit 2
        ;;
esac
