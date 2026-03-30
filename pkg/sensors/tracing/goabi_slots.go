// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:generate go run github.com/cilium/tetragon/cmd/goabi-gen

package tracing

// GoABISlotForArg returns the ABI register slot for argIndex, or -1 if unknown.
func GoABISlotForArg(symbol string, argIndex int) int {
	offsets, ok := goABIKnownFuncs[symbol]
	if !ok || argIndex >= len(offsets) {
		return -1
	}
	return offsets[argIndex]
}
