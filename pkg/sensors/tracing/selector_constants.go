// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func rewriteSelectorConstants(load *program.Program, usage selectors.SelectorUsage) {
	if !config.EnableLargeProgs() || load.RewriteConstants == nil {
		return
	}
	if load.Type == "generic_lsm" && load.Label != "lsm/generic_lsm_core" {
		return
	}
	for name, enabled := range map[string]bool{
		"HAS_MATCH_PIDS":               usage.MatchPIDs,
		"HAS_MATCH_NAMESPACES":         usage.MatchNamespaces,
		"HAS_MATCH_CAPABILITIES":       usage.MatchCapabilities,
		"HAS_MATCH_NAMESPACE_CHANGES":  usage.MatchNamespaceChanges,
		"HAS_MATCH_CAPABILITY_CHANGES": usage.MatchCapabilityChanges,
		"HAS_MATCH_BINARIES":           usage.MatchBinaries,
		"HAS_MATCH_PARENT_BINARIES":    usage.MatchParentBinaries,
		"HAS_MATCH_CMD_ARGS":           usage.MatchCmdArgs,
		"HAS_MATCH_WORKLOADS":          usage.MatchWorkloads,
		"HAS_MATCH_CEL":                usage.MatchCEL,
		"HAS_MATCH_ARG_FILTERS":        usage.MatchArgFilters,
		"HAS_MATCH_USER_CALLERS":       usage.MatchUserCallers,
	} {
		if enabled {
			load.RewriteConstants[name] = uint32(1)
		} else if _, exists := load.RewriteConstants[name]; !exists {
			load.RewriteConstants[name] = uint32(0)
		}
	}
}
