#!/usr/bin/env bash

error() {
    echo "$@" 1>&2
    exit 1
}

set -eu

PROJECT_ROOT="$(git rev-parse --show-toplevel)"
cd "$PROJECT_ROOT"
source contrib/kind/conf

if ! command -v kind &>/dev/null; then
    error "kind is not in \$PATH! Bailing out!"
fi

FORCE=0

usage() {
	echo "usage: bootstrap-kind-cluster.sh [OPTIONS]" 1>&2
	echo "OPTIONS:" 1>&2
    echo "    -f,--force    force bootstrapping even if cluster already exists" 1>&2
    echo "       --cluster  override cluster name" 1>&2
}

while [ $# -ge 1 ]; do
	if [ "$1" == "--force" ] || [ "$1" == "-f" ]; then
        FORCE=1
		shift 1
    elif [ "$1" == "--cluster" ]; then
        CLUSTER_NAME="$2"
		shift 2
    else
        usage
        exit 1
	fi
done

bootstrap_cluster() {
    if ! kind get clusters | grep "$CLUSTER_NAME" &>/dev/null; then
        echo "Creating a new cluster \"$CLUSTER_NAME\"..." 1>&2
        kind create cluster --name "$CLUSTER_NAME" --config ./contrib/kind/kind-config.yaml --wait=2m
    else
        if [ "$FORCE" != 1 ]; then
            echo "Cluster already exists... Exiting... (Re-run with -f to force.)" 1>&2
            exit 0
        else
            echo "Recreating cluster..." 1>&2
            kind delete cluster --name "$CLUSTER_NAME"
            kind create cluster --name "$CLUSTER_NAME" --config ./contrib/kind/kind-config.yaml --wait=5m
        fi
    fi

    kubectl cluster-info --context "kind-$CLUSTER_NAME"
}

bootstrap_cluster
