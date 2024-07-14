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

usage() {
	echo "usage: delete-kind-cluster.sh [OPTIONS]" 1>&2
	echo "OPTIONS:" 1>&2
    echo "       --cluster  override cluster name" 1>&2
}

while [ $# -ge 1 ]; do
    if [ "$1" == "--cluster" ]; then
        CLUSTER_NAME="$2"
		shift 2
    else
        usage
        exit 1
	fi
done


if ! kind get clusters | grep "$CLUSTER_NAME" &>/dev/null; then
    echo "Cluster $CLUSTER_NAME doesn't exist. Exiting." 1>&2
    exit 0
else
    kind delete cluster --name "$CLUSTER_NAME"
fi
