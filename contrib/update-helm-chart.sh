#!/usr/bin/env bash

set -ex

shopt -s expand_aliases
alias yq='docker run --rm -v "${PWD}":/workdir --user "$(id -u):$(id -g)" mikefarah/yq:4.27.3'

if [ -z "$1" ] || [[ ! $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  echo "USAGE: ./contrib/update-helm-chart.sh vX.Y.Z"
  exit 1
fi

version=$1
# Drop the leading "v" for Helm chart version.
semver="${version:1}"

yq -i ".version = \"$semver\"" install/kubernetes/tetragon/Chart.yaml
yq -i ".appVersion = \"$semver\"" install/kubernetes/tetragon/Chart.yaml
sed -i "s/^export TETRAGON_VERSION:=.*/export TETRAGON_VERSION:=$version/" install/kubernetes/Makefile.values
make -C install/kubernetes
