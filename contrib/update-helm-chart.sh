#!/usr/bin/env bash

set -ex

shopt -s expand_aliases
# renovate: datasource=docker
YQ_IMAGE=docker.io/mikefarah/yq:4.46.1@sha256:e4ec3062f63c5dd56c5fb79e325d24b91f1ca0d66d01cbc06ea2dd6a6ff867ab
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
