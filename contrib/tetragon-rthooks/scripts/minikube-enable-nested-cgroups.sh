#!/bin/bash
# vim:set noet ci pi ts=4 sw=4

set -o pipefail
set -e

SCRIPTPATH=$(dirname "$0")
RTHOOKSPATH=$(realpath $SCRIPTPATH/..)
make -C ${RTHOOKSPATH}/
SETUPBIN=${RTHOOKSPATH}/tetragon-oci-hook-setup

source ${SCRIPTPATH}/helpers

runtime=$(detect_runtime)
if [ "$runtime" != "crio" ]; then
	echo "crio not installed, bailing out"
	exit 1
fi

tdir=$(mktemp -d)
minikube ssh 'cat /etc/crio/crio.conf' > $tdir/crio.conf
${SETUPBIN}  patch-crio-conf enable-annotations \
	--config-file=$tdir/crio.conf \
	--output-file=$tdir/crio-patched.conf \
	--annotations='io.kubernetes.cri-o.cgroup2-mount-hierarchy-rw'
diff -u $tdir/crio.conf $tdir/crio-patched.conf || true
minikube cp $tdir/crio-patched.conf /etc/crio/crio.conf
minikube ssh sudo systemctl restart crio
