// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package tracingpolicy

// TODO
func FromYAML(data string) (TracingPolicy, error) {
	panic("non-k8s tracing policy parsing: NYI")
}
