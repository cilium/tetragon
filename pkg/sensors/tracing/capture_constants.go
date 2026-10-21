// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/config"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// Keep these bits in sync with HAS_CAPTURE_* in bpf/lib/config.h.
const (
	CaptureBTFResolve  = uint32(1 << 0)
	CapturePtRegs      = uint32(1 << 1)
	CaptureCurrentTask = uint32(1 << 2)
	CapturePreload     = uint32(1 << 3)
	CaptureMaxData     = uint32(1 << 4)
	CaptureReturnCopy  = uint32(1 << 5)
)

func captureTypeMask(argType int32) uint64 {
	if argType <= 0 || argType >= 64 {
		return 0
	}
	mask := uint64(1) << uint32(argType)
	switch argType {
	case gt.GenericFilenameType:
		mask |= uint64(1) << gt.GenericStringType
	case gt.GenericKiocb:
		mask |= uint64(1) << gt.GenericFileType
	}
	return mask
}

func rewriteCaptureConstants(load *program.Program, eventConfig *tracingapi.EventConfig) {
	if !config.EnableLargeProgs() || load.RewriteConstants == nil || eventConfig == nil {
		return
	}
	if load.Type == "generic_lsm" && load.Label != "lsm/generic_lsm_core" {
		return
	}
	mask, _ := load.RewriteConstants["CAPTURE_ARG_TYPES"].(uint64)
	var btfResolve, ptRegs, currentTask, preload, maxData, returnCopy bool
	if load.RetProbe {
		mask |= captureTypeMask(eventConfig.ArgReturn)
		mask |= captureTypeMask(eventConfig.ArgReturnCopy)
		returnCopy = eventConfig.ArgReturnCopy > 0
	} else {
		for i, argType := range eventConfig.ArgType {
			mask |= captureTypeMask(argType)
			meta := eventConfig.ArgMeta[i]
			btfResolve = btfResolve || eventConfig.BTFArg[i][0].IsInitialized != 0
			ptRegs = ptRegs || meta&argPtRegsBit != 0
			currentTask = currentTask || meta&argCurrentTaskBit != 0
			preload = preload || meta&argPreloadBit != 0
			maxData = maxData || meta&argMaxDataBit != 0
			returnCopy = returnCopy || meta&argReturnCopyBit != 0
		}
	}
	load.RewriteConstants["CAPTURE_ARG_TYPES"] = mask
	featureMask, _ := load.RewriteConstants["CAPTURE_FEATURE_MASK"].(uint32)
	for feature, enabled := range map[uint32]bool{
		CaptureBTFResolve:  btfResolve,
		CapturePtRegs:      ptRegs,
		CaptureCurrentTask: currentTask,
		CapturePreload:     preload,
		CaptureMaxData:     maxData,
		CaptureReturnCopy:  returnCopy,
	} {
		if enabled {
			featureMask |= feature
		}
	}
	load.RewriteConstants["CAPTURE_FEATURE_MASK"] = featureMask
}
