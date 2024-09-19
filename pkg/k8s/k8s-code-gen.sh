#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
source "${SCRIPT_ROOT}/vendor/k8s.io/code-generator/kube_codegen.sh"
PLURAL_EXCEPTIONS="PodInfo:PodInfo,TracingPolicyNamespaced:TracingPoliciesNamespaced"

"${SCRIPT_ROOT}"/tools/controller-gen crd paths=./apis/... output:dir=apis/cilium.io/client/crds/v1alpha1

kube::codegen::gen_client \
    ./apis \
    --with-watch \
    --output-dir "client" \
    --output-pkg "github.com/cilium/tetragon/pkg/k8s/client" \
    --plural-exceptions ${PLURAL_EXCEPTIONS} \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
    ./apis

