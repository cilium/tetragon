// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package kernel

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
)

func GetTaintedBitsTypes(taints uint64) []tetragon.TaintedBitsType {
	if taints == 0 {
		// Not Tainted
		return nil
	}

	var bits []tetragon.TaintedBitsType

	if taints&uint64(tetragon.TaintedBitsType_TAINT_PROPRIETARY_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_PROPRIETARY_MODULE)
	}

	if taints&uint64(tetragon.TaintedBitsType_TAINT_FORCED_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_FORCED_MODULE)
	}

	if taints&uint64(tetragon.TaintedBitsType_TAINT_FORCED_UNLOAD_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_FORCED_UNLOAD_MODULE)
	}

	if taints&uint64(tetragon.TaintedBitsType_TAINT_STAGED_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_STAGED_MODULE)
	}

	if taints&uint64(tetragon.TaintedBitsType_TAINT_OUT_OF_TREE_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_OUT_OF_TREE_MODULE)
	}

	if taints&uint64(tetragon.TaintedBitsType_TAINT_UNSIGNED_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_UNSIGNED_MODULE)
	}

	if taints&uint64(tetragon.TaintedBitsType_TAINT_KERNEL_LIVE_PATCH_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_KERNEL_LIVE_PATCH_MODULE)
	}

	if taints&uint64(tetragon.TaintedBitsType_TAINT_TEST_MODULE) != 0 {
		bits = append(bits, tetragon.TaintedBitsType_TAINT_TEST_MODULE)
	}

	return bits
}
