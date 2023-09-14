#! /bin/bash

error() {
    echo "$@" 1>&2
    exit 1
}

set -eu

PROJECT_ROOT="$(git rev-parse --show-toplevel)"
cd "$PROJECT_ROOT"
source contrib/localdev/conf

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
    echo "    -i,--image     <IMAGE:TAG> override image for agent" 1>&2
    echo "    -o, --operator <IMAGE:TAG> override image for operator" 1>&2
    echo "    -v, --values   <PATH>      additional values file for helm install" 1>&2
    echo "       --cluster               override cluster name" 1>&2
}

FORCE=0
IMAGE=""
OPERATOR=""
VALUES=""

while [ $# -ge 1 ]; do
	if [ "$1" == "--force" ] || [ "$1" == "-f" ]; then
        FORCE=1
		shift 1
    elif [ "$1" == "--image" ] || [ "$1" == "-i" ]; then
        IMAGE=$2
		shift 2
    elif [ "$1" == "--operator" ] || [ "$1" == "-o" ]; then
        OPERATOR=$2
		shift 2
    elif [ "$1" == "--values" ] || [ "$1" == "-v" ]; then
        VALUES=$2
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
    helm uninstall -n kube-system tetragon || true
fi

# Set helm options
declare -a helm_opts=("--namespace" "kube-system")
if [ -n "$IMAGE" ]; then
    helm_opts+=("--set" "tetragon.image.override=$IMAGE")
    if [ "$IS_KIND" == 1 ]; then
        kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"
    fi
fi
if [ -n "$OPERATOR" ]; then
    helm_opts+=("--set" "tetragonOperator.image.override=$OPERATOR")
    if [ "$IS_KIND" == 1 ]; then
        kind load docker-image "$OPERATOR" --name "$CLUSTER_NAME"
    fi
fi
if [ -n "$VALUES" ]; then
    helm_opts+=("--values" "$VALUES")
fi
helm_opts+=("tetragon" "./install/kubernetes")

if [ "$IS_KIND" == 1 ]; then
	# NB: configured in kind-config.yaml
	helm_opts+=("--set" "tetragon.hostProcPath=/procHost")
fi

echo "Installing Tetragon in cluster..." 1>&2
helm upgrade --install "${helm_opts[@]}"

echo "Waiting for Tetragon deployment..." 1>&2
kubectl rollout status -n kube-system ds/tetragon -w --timeout 5m
