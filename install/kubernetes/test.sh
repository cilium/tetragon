#!/bin/bash

set -e
set -o pipefail
shopt -s expand_aliases

# make this script executable from anywhere
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

alias helm='docker run --rm -v $(pwd):/apps alpine/helm:3.3.4'
alias kubeconform='docker run --rm -i ghcr.io/yannh/kubeconform:v0.6.4-alpine@sha256:e68a0b638c6e9b76f1b7d58b4ec94340ef3b6601db25b2e40b29e3ac2d68e4bf'
helm dependency update .
helm lint . --with-subcharts
helm template tetragon . | kubeconform --strict --schema-location default

# Update README.md.
docker run --rm -v "$(pwd):/helm-docs" -u "$(id -u)" jnorwood/helm-docs:v1.11.0@sha256:66c8f4164dec860fa5c1528239c4aa826a12485305b7b224594b1a73f7e6879a
./export-doc.sh ../../docs/content/en/docs/reference/helm-chart.md
