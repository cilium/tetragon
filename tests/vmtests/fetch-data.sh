#!/bin/bash

set -eu -o pipefail

OCIORG=quay.io/lvh-images
ROOTIMG=$OCIORG/root-images
KERNIMG=$OCIORG/kernel-images
CONTAINER_ENGINE=docker
DEST_DIR="tests/vmtests/test-data"

kernel_vers=""
base_image=0

usage() {
	echo "Usage: $0 [-k kernel_ver] [-b]"
	echo "-k kver: fetch kernel version kver"
	echo "-b fetch base image"
	echo "Example: $0 -b -k bpf-next -k 5.10"
}

while getopts "hk:b" option
do
	case $option in
		h)
			usage
			exit 0
			;;
		k)
			kernel_vers="$kernel_vers ${OPTARG}"
			;;
		b)
			base_image=1
			;;
	esac
done

if [ $base_image  = 0 ] && [ -z $kernel_vers ] ; then
	usage
	exit 0
fi

set -x

if [ $base_image  = 1 ]; then
	mkdir -p $DEST_DIR/images
	$CONTAINER_ENGINE pull $ROOTIMG
	rm -f $DEST_DIR/images/base.qcow2*
	x=$($CONTAINER_ENGINE create $ROOTIMG)
	$CONTAINER_ENGINE cp $x:/data/images/base.qcow2.zst  $DEST_DIR/images/base.qcow2.zst
	zstd --decompress $DEST_DIR/images/base.qcow2.zst
	$CONTAINER_ENGINE rm $x
fi

for ver in $kernel_vers; do
	mkdir -p $DEST_DIR/kernels
	img="$KERNIMG:$ver"
	$CONTAINER_ENGINE pull $img
	rm -rf $DEST_DIR/kernels/$ver
	x=$($CONTAINER_ENGINE create $img)
	$CONTAINER_ENGINE cp $x:/data/kernels/$ver  $DEST_DIR/kernels
	$CONTAINER_ENGINE rm $x
done
