#!/bin/bash
# vim:set noet ci pi ts=4 sw=4

set -o pipefail
set -e

if [ "$1" != "install" ]; then
	SCRIPTPATH=$(dirname "$0")
	source ${SCRIPTPATH}/helpers

	runtime=$(detect_runtime)
	if [ "$runtime" != "crio" ]; then
		echo "crio not installed, bailing out"
		exit 1
	fi

	name=$(basename "$0")
	minikube cp $0 /tmp/$name
	minikube ssh sudo chmod +x /tmp/$name
	minikube ssh sudo /tmp/$name install
	exit 0
fi

set -x

echo "Running inside minikube: $(uname -a)"
crio_v=$(crio --version | sed -ne 's/^Version:[[:space:]]\+\(.\+\)/\1/p')
echo "crio version: $crio_v"
crun_v=$(crun --version | sed -ne 's/^crun version[[:space:]]\+\(.\+\)/\1/p')
echo "old crun version: $crun_v"

# cleanup everything
systemctl stop kubelet
crictl ps -a -q | xargs crictl stop
crictl ps -a -q | xargs crictl rm
crictl pods -q | xargs crictl stopp
crictl pods -q | xargs crictl rmp
systemctl stop crio

cd /tmp
tarball=cri-o.amd64.v${crio_v}.tar.gz
if [ -f "${tarball}" ]; then
	echo "tarball ${tarball} exists, skipping download"
else
	curl -sOL -C - https://storage.googleapis.com/cri-o/artifacts/${tarball}
fi
rm -rf cri-o
tar zxf $tarball
cd cri-o
cp ./bin/crio-{conmon,conmonrs,crun} /usr/bin
crio_crun_v=$(crio-crun --version | sed -ne 's/^crun version[[:space:]]\+\(.\+\)/\1/p')
echo "new crun version: $crio_crun_v"

fname=$(mktemp -t crio-crun-conf.XXXXX)
cat >$fname <<EOF
[crio.runtime]
default_runtime = "crun"

[crio.runtime.runtimes.crun]
runtime_path = "/usr/bin/crio-crun"
monitor_path = "/usr/bin/crio-conmon"
allowed_annotations = [
    "io.containers.trace-syscall",
]
EOF
chmod go+r ${fname}
chown root:root ${fname}
cp $fname /etc/crio/crio.conf.d/10-crun.conf
systemctl start crio
systemctl start kubelet
