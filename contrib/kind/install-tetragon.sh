#!/usr/bin/env bash

error() {
    echo "$@" 1>&2
    exit 1
}

set -eu

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/../.."
source "$PROJECT_ROOT/contrib/kind/conf"

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

BASE_VALUES="${TETRAGON_KIND_BASE_VALUES:-"$PROJECT_ROOT/contrib/kind/values.yaml"}"
HELM_CHART="${TETRAGON_KIND_HELM_CHART:-"$PROJECT_ROOT/install/kubernetes/tetragon"}"

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

# Uninstall if desired
if [ "$FORCE" == 1 ]; then
    helm uninstall -n "$NAMESPACE" tetragon || true
fi

# Create namespace if needed
kubectl create namespace "$NAMESPACE" &>/dev/null || true

# Detect if we're running in kind and load images if so
set +e
kubectl config current-context | grep -q '^kind' &>/dev/null
if [ $? == 0 ]; then
    if ! command -v yq &>/dev/null; then
        error "yq is not in \$PATH! Bailing out!"
    fi
    if ! command -v kind &>/dev/null; then
        error "kind is not in \$PATH! Bailing out!"
    fi
    image=$(yq -r '.tetragon.image.override' "$BASE_VALUES")
    image_operator=$(yq -r '.tetragonOperator.image.override' "$BASE_VALUES")
    kind load docker-image "$image" --name "$CLUSTER_NAME"
    kind load docker-image "$image_operator" --name "$CLUSTER_NAME"
fi
set -e

# Set helm options
declare -a extra_opts=()
if [ -n "$VALUES" ]; then
    extra_opts+=("-f" "$VALUES")
fi

echo "Installing Tetragon in cluster..." 1>&2
helm upgrade --install tetragon "$HELM_CHART" \
  -n "$NAMESPACE" \
  -f "$BASE_VALUES" "${extra_opts[@]}"

echo "Waiting for Tetragon deployment..." 1>&2
kubectl rollout status -n "$NAMESPACE" ds/tetragon -w --timeout 5m
