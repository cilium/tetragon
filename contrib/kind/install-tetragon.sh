#! /bin/bash

error() {
    echo "$@" 1>&2
    exit 1
}

set -eu

PROJECT_ROOT="$(git rev-parse --show-toplevel)"
cd "$PROJECT_ROOT"
source contrib/kind/conf

if ! command -v helm &>/dev/null; then
    error "helm is not in \$PATH! Bailing out!"
fi

if ! command -v kubectl &>/dev/null; then
    error "kubectl is not in \$PATH! Bailing out!"
fi

usage() {
	echo "usage: install-tetragon.sh [OPTIONS]" 1>&2
	echo "OPTIONS:" 1>&2
    echo "    -f,--force                 force a helm uninstall before installing" 1>&2
    echo "    -v,--values    <PATH>      additional values file for helm install" 1>&2
    echo "    -n,--namespace <NAME>      override namespace (default tetragon)" 1>&2
    echo "       --cluster               override cluster name" 1>&2
}

BASE_VALUES="${TETRAGON_KIND_BASE_VALUES:-contrib/kind/values.yaml}"

FORCE=0
VALUES=""
NAMESPACE="tetragon"

while [ $# -ge 1 ]; do
	if [ "$1" == "--force" ] || [ "$1" == "-f" ]; then
        FORCE=1
		shift 1
    elif [ "$1" == "--values" ] || [ "$1" == "-v" ]; then
        VALUES=$2
		shift 2
    elif [ "$1" == "--namespace" ] || [ "$1" == "-n" ]; then
        NAMESPACE=$2
		shift 2
    elif [ "$1" == "--cluster" ]; then
        CLUSTER_NAME="$2"
		shift 2
    else
        usage
        exit 1
	fi
done

# Detect if we are running in kind
set +e
kubectl config current-context | grep -q '^kind' &>/dev/null
if [ $? == 0 ]; then
    IS_KIND=1
else
    IS_KIND=0
fi
set -e

# Uninstall if desired
if [ "$FORCE" == 1 ]; then
    helm uninstall -n "$NAMESPACE" tetragon || true
fi

# Create namespace if needed
kubectl create namespace "$NAMESPACE" &>/dev/null || true

# Load images into kind
if [ "$IS_KIND" == 1 ]; then
    image=$(yq '.tetragon.image.override' "$BASE_VALUES")
    image_operator=$(yq '.tetragonOperator.image.override' "$BASE_VALUES")
    kind load docker-image "$image" --name "$CLUSTER_NAME"
    kind load docker-image "$image_operator" --name "$CLUSTER_NAME"
fi

# Set helm options
declare -a helm_opts=("--namespace" "$NAMESPACE" "--values" "$BASE_VALUES")
if [ -n "$VALUES" ]; then
    helm_opts+=("--values" "$VALUES")
fi
helm_opts+=("tetragon" "./install/kubernetes/tetragon")

echo "Installing Tetragon in cluster..." 1>&2
helm upgrade --install "${helm_opts[@]}"

echo "Waiting for Tetragon deployment..." 1>&2
kubectl rollout status -n "$NAMESPACE" ds/tetragon -w --timeout 5m
