// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build tools

package tools

import (
	_ "k8s.io/code-generator"
	_ "k8s.io/code-generator/cmd/client-gen"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
