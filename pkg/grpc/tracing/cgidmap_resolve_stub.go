// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build windows || nok8s

package tracing

func resolveContainerID(_ uint64) string {
	return ""
}
