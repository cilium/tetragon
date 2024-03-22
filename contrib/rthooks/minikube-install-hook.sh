#!/bin/bash

set -o pipefail
set -e

SCRIPTPATH=$(dirname "$0")

HOOKNAME=/opt/tetragon/tetragon-oci-hook
HOOKDIR=$(dirname $HOOKNAME)
BASEHOOKNAME=$(basename $HOOKNAME)
LOCALHOOK="$SCRIPTPATH/$BASEHOOKNAME/$BASEHOOKNAME"

usage() {
        echo "Usage: $0 [-l|--log] [-d|--debug] [-k|--keep-tmpdir]"
        echo "   -l|--log:          configure hook to just log and not attempt to contact the agent"
        echo "   -d|--debug:        configure hook to log debug info"
        echo "   -k|--keep-tmpdir:  do not delete the temporary directory"
        echo "   -i|--install-hook: only install hook, do not mess with runtime conf"
}

declare -A conf=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--log)
      conf["disable_grpc"]="true"
      shift
      ;;
    -d|--debug)
      conf["log_level"]="debug"
      shift
      ;;
    -k|--keep-tmpdir)
      keep_tmpdir=1
      shift
      ;;
    -i|--install-hook)
      install_hook=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*|--*)
      echo "Unknown option $1"
      usage
      exit 1
      ;;
    *)
      echo "Unexpected argument"
      usage
      exit 1
      ;;
  esac
done

xdir=$(mktemp -d /tmp/minikube-tetragon-oci-hook-XXXXXX)
echo "temporary directory: $xdir"
if [ ! "$keep_tmpdir" == "1" ]; then
        trap 'echo removing temporary directory; rm -rf -- "$xdir"' EXIT
fi

set -x

make -C ${SCRIPTPATH}/tetragon-oci-hook
SETUPBIN=${SCRIPTPATH}/tetragon-oci-hook/tetragon-oci-hook-setup


minikube ssh -- sudo mkdir -p $HOOKDIR
if [ ${#conf[@]} -gt 0 ]; then
        for k in "${!conf[@]}"
        do
                echo "$k"
                echo "${conf[$k]}"
        done | jq -R -n 'reduce inputs as $k ({}; . + { ($k): (input)})' > $xdir/tetragon-oci-hook.json
        minikube cp $xdir/tetragon-oci-hook.json $HOOKDIR/tetragon-oci-hook.json
fi

minikube cp $LOCALHOOK $HOOKNAME
minikube ssh -- sudo chmod +x $HOOKNAME

if [ "$install_hook" == "1" ]; then
    echo "Only supposed to install hook, bailing out"
    exit 0
fi

kubeletcmd=$(minikube ssh -- 'sudo tr \\0 " "  < /proc/"$(pgrep kubelet)"/cmdline')
if [[ "$kubeletcmd" =~ "containerd.sock" ]]; then
	echo "Found containerd runtime"
	mapfile -d '' JQCMD <<-EOF
	. += { "hooks": {
		"createRuntime": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createRuntime"] }],
		"createContainer": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createContainer"] }],
	}}
	EOF

        minikube ssh ctr oci spec | jq "$JQCMD" > $xdir/base-spec.json
        minikube cp $xdir/base-spec.json /etc/containerd/base-spec.json
        minikube ssh cat /etc/containerd/config.toml > $xdir/config.old.toml
        go run $SCRIPTPATH/patch-containerd-conf.go --config-file $xdir/config.old.toml --output $xdir/config.toml
        minikube cp $xdir/config.toml /etc/containerd/config.toml
        minikube ssh sudo systemctl restart containerd

        exit 0
fi

if [[ "$kubeletcmd" =~ "crio.sock" ]]; then
	$SETUPBIN print-config --interface=oci-hooks --binary=$HOOKNAME > $xdir/hook.json
        minikube cp $xdir/hook.json /usr/share/containers/oci/hooks.d/teragon-oci-hook.json
	exit 0
fi

set +x
echo "Unknown runtime, bailing out"
echo "kubeletcmd: $kubeletcmd"
exit 1
