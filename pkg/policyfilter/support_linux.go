// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import "github.com/cilium/tetragon/pkg/kernels"

func NSMapUpdateSupportedFromBPF() bool {
	return !kernels.IsKernelVersionLessThan("5.4")
}
