#!/usr/bin/env bash

set -ex

shopt -s expand_aliases
# renovate: datasource=docker
YQ_IMAGE=docker.io/mikefarah/yq:4.47.1@sha256:b9285dd3b0bea3c34d0c54415dd48d767dabd9644d489bd6e253660847b58419
alias yq="docker run --rm -v \"${PWD}\":/workdir --user \"$(id -u):$(id -g)\" $YQ_IMAGE"

if [ -z "$1" ] || [[ ! $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  echo "USAGE: ./contrib/update-helm-chart.sh vX.Y.Z"
  exit 1
fi

version=$1
# Drop the leading "v" for Helm chart version.
semver="${version:1}"

yq -i ".version = \"$semver\"" install/kubernetes/tetragon/Chart.yaml
yq -i ".appVersion = \"$semver\"" install/kubernetes/tetragon/Chart.yaml
yq -i ".tetragon.image.tag = \"$version\"" install/kubernetes/tetragon/values.yaml
yq -i ".tetragonOperator.image.tag = \"$version\"" install/kubernetes/tetragon/values.yaml
