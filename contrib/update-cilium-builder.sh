#!/bin/bash

# script to update cilium builder images, and effectively the go version with which we build our
# images.

# get latest image from cilium repo
new_image=$(wget https://raw.githubusercontent.com/cilium/cilium/master/images/cilium/Dockerfile -q -O - | sed -ne 's/^ARG CILIUM_BUILDER_IMAGE=//p')

# find files that we need to update, and update them.
myname=$(basename $0)
for file in $(git grep -l quay.io/cilium/cilium-builder ":(exclude)*$myname"); do
        sed -i -e "s%quay.io/cilium/cilium-builder[^ ]\+%${new_image}%" $file
done

make vendor
echo "New go version: $(docker run $new_image go version)"
