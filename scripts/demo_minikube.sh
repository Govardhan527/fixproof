#!/usr/bin/env bash
# A minikube node that runs Docker Engine through cri-dockerd (ADR-0010 Amendment 2): the kind
# demo covers containerd, this covers the other common runtime, and minikube's default. It runs
# the fixproof-docker workloads (scripts/demo_workloads.py --docker), images from Docker Hub
# written with Docker's short names and one image loaded with no registry digest, and writes a
# kubeconfig for fixproof's read-only account. The CI `integration-docker-runtime` job runs it.
#   scripts/demo_minikube.sh up WORKDIR      needs Docker, curl and uv
#   scripts/demo_minikube.sh down WORKDIR
# WORKDIR receives bin/ (minikube and kubectl, checksum-verified), admin.kubeconfig and
# reader.kubeconfig. Your own kubectl config is not touched.
set -euo pipefail

PROFILE=fixproof-docker  # also the kubeconfig context name
NAMESPACE=fixproof-docker  # demo_workloads.DOCKER_NAMESPACE
LOCAL_IMAGE=fixproof-docker-local:it  # demo_workloads.DOCKER_LOCAL
MINIKUBE_VERSION=v1.39.0
MINIKUBE_SHA256=b738496da01be06bbaf80c688f57ce25acd3849fbb518155f3a88e03ef555aa4
KUBERNETES_VERSION=v1.37.0  # minikube v1.39.0's default
KUBECTL_VERSION=v1.37.1
KUBECTL_SHA256=65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8

repo="$(cd "$(dirname "$0")/.." && pwd)"
command="${1:?usage: demo_minikube.sh up|down WORKDIR}"
work="${2:?usage: demo_minikube.sh up|down WORKDIR}"
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
    minikube start --profile "$PROFILE" --driver=docker --container-runtime=docker \
        --kubernetes-version="$KUBERNETES_VERSION" --wait=all
    kubectl get nodes -o wide  # CONTAINER-RUNTIME shows docker://
}

load_local_image() {  # no repository digest on the node: the pod's imageID is docker://sha256:...
    docker build --quiet --label fixproof.fixture.loaded=minikube --tag "$LOCAL_IMAGE" \
        "$repo/tests/fixtures/images/requests-2.31.0" > /dev/null
    minikube --profile "$PROFILE" image load "$LOCAL_IMAGE"
}

deploy() {
    kubectl apply -f "$repo/deploy/kubernetes/fixproof-reader.yaml"
    kubectl create namespace "$NAMESPACE"
    kubectl apply -n "$NAMESPACE" -f "$repo/deploy/kubernetes/fixproof-reader-role.yaml"
    uv run --frozen python "$repo/scripts/demo_workloads.py" --docker | kubectl apply -f -
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
