#!/bin/bash

set -o pipefail
set -e

SCRIPTPATH=$(dirname "$0")
RTHOOKSPATH=$(realpath "$SCRIPTPATH/..")
CLUSTER_NAME="kind"

usage() {
	echo "Usage: $0 [--cluster NAME] [-h|--help]"
	echo ""
	echo "This script sets containerd configuration to enable NRI support. "
	echo "It assumes a single-node kind cluster named '${CLUSTER_NAME}' as created in the documentation."
	echo ""
	echo "Options:"
	echo "     --cluster: override kind cluster name (default: ${CLUSTER_NAME})"
}

while [[ $# -gt 0 ]]; do
	case $1 in
		--cluster)
			CLUSTER_NAME="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option $1"
			usage
			exit 1
			;;
	esac
done

NODE=$(kind get nodes --name "$CLUSTER_NAME" | head -n 1)
if [ -z "$NODE" ]; then
	echo "No kind nodes found for cluster \"$CLUSTER_NAME\""
	exit 1
fi

xdir=$(mktemp -d /tmp/kind-nri-setup-XXXXXX)
trap 'rm -rf -- "$xdir"' EXIT

make -C "${RTHOOKSPATH}/"
SETUPBIN="${RTHOOKSPATH}/tetragon-oci-hook-setup"

echo "Enabling containerd NRI support on $NODE"
docker cp "${NODE}:/etc/containerd/config.toml" "$xdir/config.old.toml"
"$SETUPBIN" patch-containerd-conf enable-nri --config-file "$xdir/config.old.toml" --output "$xdir/config.toml"
diff -u "$xdir/config.old.toml" "$xdir/config.toml" || true
docker cp "$xdir/config.toml" "${NODE}:/etc/containerd/config.toml"
docker exec "$NODE" systemctl restart containerd
echo "NRI enabled on $NODE, containerd restarted"
