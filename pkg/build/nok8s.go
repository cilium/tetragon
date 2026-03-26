// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package build

func K8sEnabled() bool {
	return false
}
