// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type argPrinter struct {
	ty      int
	index   int
	maxData bool
	label   string
}

const (
	argReturnCopyBit = 1 << 4
	argMaxDataBit    = 1 << 5
)

func argReturnCopy(meta int) bool {
	return meta&argReturnCopyBit != 0
}

// meta value format:
// bits
//
//	0-3 : SizeArgIndex
//	  4 : ReturnCopy
//	  5 : MaxData
func getMetaValue(arg *v1alpha1.KProbeArg) (int, error) {
	var meta int

	if arg.SizeArgIndex > 0 {
		if arg.SizeArgIndex > 15 {
			return 0, fmt.Errorf("invalid SizeArgIndex value (>15): %v", arg.SizeArgIndex)
		}
		meta = int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		meta = meta | argReturnCopyBit
	}
	if arg.MaxData {
		meta = meta | argMaxDataBit
	}
	return meta, nil
}

// getTracepointMetaArg is a temporary helper to find meta values while tracepoint
// converts into new CRD and config formats.
func getTracepointMetaValue(arg *v1alpha1.KProbeArg) int {
	if arg.SizeArgIndex > 0 {
		return int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		return -1
	}
	return 0
}
