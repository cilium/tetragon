#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

K8S_PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/.."
CODEGEN_PKG=$K8S_PKG/vendor/k8s.io/code-generator

source "${CODEGEN_PKG}/kube_codegen.sh"

PLURAL_EXCEPTIONS=${1:-"TracingPolicyNamespaced:TracingPoliciesNamespaced,PodInfo:PodInfo"}

kube::codegen::gen_client \
    --with-watch \
    --output-dir "${K8S_PKG}/client" \
    --output-pkg "github.com/cilium/tetragon/pkg/k8s/client" \
    --plural-exceptions ${PLURAL_EXCEPTIONS} \
    --boilerplate "${K8S_PKG}/hack/custom-boilerplate.go.txt" \
    "${K8S_PKG}/apis"

kube::codegen::gen_helpers \
    --boilerplate "${K8S_PKG}/hack/custom-boilerplate.go.txt" \
    "${K8S_PKG}/apis"
