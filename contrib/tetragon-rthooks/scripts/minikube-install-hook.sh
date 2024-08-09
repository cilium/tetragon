#!/bin/bash
# vim:set noet ci pi ts=4 sw=4

set -o pipefail
set -e

SCRIPTPATH=$(dirname "$0")
RTHOOKSPATH=$(realpath $SCRIPTPATH/..)
HOOKNAME=/opt/tetragon/tetragon-oci-hook
HOOKDIR=$(dirname $HOOKNAME)
BASEHOOKNAME=$(basename $HOOKNAME)
LOCALHOOK="$RTHOOKSPATH/$BASEHOOKNAME"

source ${SCRIPTPATH}/helpers

usage() {
	echo "Usage: $0 [-l|--log] [-d|--debug] [-k|--keep-tmpdir]"
	echo "   -l|--log:          configure hook to just log and not attempt to contact the agent"
	echo "   -d|--debug:        configure hook to log debug info"
	echo "   -k|--keep-tmpdir:  do not delete the temporary directory"
	echo "   -i|--install-hook: only install hook, do not mess with runtime conf"
	echo "      --nri:          install nri hook (only for containerd)"
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
    --nri)
      nri=1
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

runtime=$(detect_runtime)

xdir=$(mktemp -d /tmp/minikube-tetragon-oci-hook-XXXXXX)
echo "temporary directory: $xdir"
if [ ! "$keep_tmpdir" == "1" ]; then
	trap 'echo removing temporary directory; rm -rf -- "$xdir"' EXIT
fi

set -x

make -C ${RTHOOKSPATH}/
SETUPBIN=${RTHOOKSPATH}/tetragon-oci-hook-setup


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


install_containerd() {
    if [ "$nri" == "1" ]; then
	echo "Enabling containerd NRI hook"
	minikube ssh cat /etc/containerd/config.toml > $xdir/config.old.toml
	$SETUPBIN patch-containerd-conf enable-nri --config-file $xdir/config.old.toml --output $xdir/config.toml
	diff -u $xdir/config.old.toml $xdir/config.toml || true
	minikube cp $xdir/config.toml /etc/containerd/config.toml
	minikube ssh sudo systemctl restart containerd
    else
	echo "Installing containerd OCI hook"
	mapfile -d '' JQCMD <<-EOF
	. += { "hooks": {
	    "createRuntime": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createRuntime"] }],
	    "createContainer": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createContainer"] }],
	}}
	EOF

	minikube ssh ctr oci spec | jq "$JQCMD" > $xdir/base-spec.json
	minikube cp $xdir/base-spec.json /etc/containerd/base-spec.json
	minikube ssh cat /etc/containerd/config.toml > $xdir/config.old.toml
	$SETUPBIN patch-containerd-conf add-oci-hook --config-file $xdir/config.old.toml --output $xdir/config.toml
	diff -u $xdir/config.old.toml $xdir/config.toml || true
	minikube cp $xdir/config.toml /etc/containerd/config.toml
	minikube ssh sudo systemctl restart containerd
    fi
}

install_crio() {
	echo "Installing CRIO OCI hook"
	$SETUPBIN print-config --interface=oci-hooks --binary=$HOOKNAME > $xdir/hook.json
	minikube cp $xdir/hook.json /usr/share/containers/oci/hooks.d/teragon-oci-hook.json
}


case $runtime in
  containerd)
	install_containerd
	;;
  crio)
	install_crio
	;;
  *)
    echo "Unknown runtime"
    exit 1
    ;;
esac
