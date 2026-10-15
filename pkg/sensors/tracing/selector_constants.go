// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	MatchPIDsMask          = uint32(1 << 1)
	MatchNamespaces        = uint32(1 << 2)
	MatchCapabilities      = uint32(1 << 3)
	MatchNamespaceChanges  = uint32(1 << 4)
	MatchCapabilityChanges = uint32(1 << 5)
	MatchBinaries          = uint32(1 << 6)
	MatchParentBinaries    = uint32(1 << 7)
	MatchCmdArgs           = uint32(1 << 8)
	MatchWorkloads         = uint32(1 << 9)
	MatchUserCallers       = uint32(1 << 10)
	MatchCEL               = uint32(1 << 11)
	MatchArgFilters        = uint32(1 << 12)
)

func rewriteSelectorConstants(load *program.Program, usage selectors.SelectorUsage) {
	if !config.EnableLargeProgs() || load.RewriteConstants == nil {
		return
	}
	if load.Type == "generic_lsm" && load.Label != "lsm/generic_lsm_core" {
		return
	}

	// preserve FEATURE_MASK from other probes sharing this program
	featureMask, _ := load.RewriteConstants["FEATURE_MASK"].(uint32)
	for idx, enabled := range map[uint32]bool{
		MatchPIDsMask:          usage.MatchPIDs,
		MatchNamespaces:        usage.MatchNamespaces,
		MatchCapabilities:      usage.MatchCapabilities,
		MatchNamespaceChanges:  usage.MatchNamespaceChanges,
		MatchCapabilityChanges: usage.MatchCapabilityChanges,
		MatchBinaries:          usage.MatchBinaries,
		MatchParentBinaries:    usage.MatchParentBinaries,
		MatchCmdArgs:           usage.MatchCmdArgs,
		MatchWorkloads:         usage.MatchWorkloads,
		MatchUserCallers:       usage.MatchUserCallers,
		MatchCEL:               usage.MatchCEL,
		MatchArgFilters:        usage.MatchArgFilters,
	} {
		if enabled {
			featureMask |= idx
		}
	}
	load.RewriteConstants["FEATURE_MASK"] = featureMask
}
