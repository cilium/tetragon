// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package dump

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "dump",
		Short:        "dump information",
		Hidden:       true,
		SilenceUsage: true,
	}

	ret.AddCommand(
		policyfilterCmd(),
	)

	return ret
}

func policyfilterCmd() *cobra.Command {

	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, policyfilter.MapName)

	ret := &cobra.Command{
		Use:   "policyfilter",
		Short: "dump policyfilter state",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			dumpPolicyfilterState(mapFname)
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")

	return ret
}

func dumpPolicyfilterState(fname string) {
	m, err := policyfilter.OpenMap(fname)
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to open policyfilter map")
		return
	}

	data, err := m.Dump()
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to open policyfilter map")
		return
	}

	if len(data) == 0 {
		fmt.Printf("(empty)\n")
		return
	}

	for polId, cgIDs := range data {
		ids := make([]string, 0, len(cgIDs))
		for id := range cgIDs {
			ids = append(ids, strconv.FormatUint(uint64(id), 10))
		}
		fmt.Printf("%d: %s\n", polId, strings.Join(ids, ","))
	}
}
