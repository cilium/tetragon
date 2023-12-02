#!/bin/bash

set -e
set -o pipefail
shopt -s expand_aliases

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TETRAGON_CHART="$SCRIPT_DIR/tetragon"

alias helm='docker run --rm -v $TETRAGON_CHART:/apps alpine/helm:3.3.4'
alias kubeval='docker run --rm -i garethr/kubeval:0.15.0@sha256:6962d8ecbb7839637667f66e6703e6ebaae0c29dfe93a31d9968fba4324c7b8d'
helm dependency update .
helm lint . --with-subcharts
helm template tetragon . | kubeval --strict --additional-schema-locations https://raw.githubusercontent.com/joshuaspence/kubernetes-json-schema/master

# Update README.md and documentation
docker run --rm -v "$TETRAGON_CHART:/helm-docs" -u "$(id -u)" jnorwood/helm-docs:v1.11.0@sha256:66c8f4164dec860fa5c1528239c4aa826a12485305b7b224594b1a73f7e6879a
"$SCRIPT_DIR/export-doc.sh" "$SCRIPT_DIR/../../docs/content/en/docs/reference/helm-chart.md"
