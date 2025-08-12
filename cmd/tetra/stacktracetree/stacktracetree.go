// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package stacktracetree

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	sttCmd := &cobra.Command{
		Use:   "stacktrace-tree",
		Short: "Manage stacktrace trees",
	}

	sttPrintCmd := &cobra.Command{
		Use:   "print <tree-name>",
		Short: "Print stacktrace tree",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			stt := args[0]
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				sttPrint(ctx, cli, stt)
			})
		},
	}
	sttCmd.AddCommand(sttPrintCmd)

	return sttCmd
}

func sttPrint(ctx context.Context, client tetragon.FineGuidanceSensorsClient, stt string) {
	res, err := client.GetStackTraceTree(ctx, &tetragon.GetStackTraceTreeRequest{Name: stt})
	if err != nil {
		fmt.Printf("error printing stt %s: %s\n", stt, err)
		return
	}

	// NB: leave this here, in case we want to add a json option at some point
	if false {
		resJSON, err := json.Marshal(res)
		if err != nil {
			fmt.Printf("error marshaling stt %s: %s\n", stt, err)
			return
		}
		fmt.Printf("%s\n", string(resJSON))
	}

	sttPrintNodeTree(res.Root, 0)
}

func sttPrintNodeTree(node *tetragon.StackTraceNode, level int) {
	identSpace := "    "
	indent := strings.Repeat(identSpace, level)
	fmt.Printf("%s0x%x (%s) count:%d\n", indent, node.Address.Address, node.Address.Symbol, node.Count)

	nchildren := len(node.Children)
	for _, child := range node.Children {
		sttPrintNodeTree(child, level+1)
	}

	// This is a leaf, so we also print label counters
	if nchildren == 0 {
		for _, label := range node.Labels {
			fmt.Printf("%s%s%s count:%d\n", indent, identSpace, label.Key, label.Count)
		}
	}
}
