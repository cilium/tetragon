#!/bin/bash

set -o pipefail
set -e

SCRIPTPATH=$(dirname "$0")

HOOKNAME=/opt/tetragon/tetragon-oci-hook
BASEHOOKNAME=$(basename $HOOKNAME)
LOCALHOOK="$SCRIPTPATH/$BASEHOOKNAME/$BASEHOOKNAME"

xdir=$(mktemp -d /tmp/minikube-containerd-hook-XXXXXX)
trap 'echo removing temporar directory; rm -rf -- "$xdir"' EXIT
echo "temporary directory: $xdir"

set -x

go build -o $LOCALHOOK  $SCRIPTPATH/tetragon-oci-hook

mapfile -d '' JQCMD << EOF
. += { "hooks": {
	"createRuntime": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createRuntime"] }],
	"createContainer": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createContainer"] }],
}}
EOF

minikube ssh -- sudo mkdir -p /opt/tetragon
minikube cp $LOCALHOOK $HOOKNAME
minikube ssh -- sudo chmod +x $HOOKNAME

minikube ssh ctr oci spec | jq "$JQCMD" > $xdir/base-spec.json
minikube cp $xdir/base-spec.json /etc/containerd/base-spec.json
minikube ssh cat /etc/containerd/config.toml > $xdir/config.old.toml
go run $SCRIPTPATH/patch-containerd-conf.go --config-file $xdir/config.old.toml --output $xdir/config.toml
minikube cp $xdir/config.toml /etc/containerd/config.toml
minikube ssh sudo systemctl restart containerd
