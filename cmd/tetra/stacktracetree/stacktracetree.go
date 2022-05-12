// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stacktracetree

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/isovalent/tetragon-oss/api/v1/fgs"
	"github.com/isovalent/tetragon-oss/cmd/tetra/common"

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
		Run: func(cmd *cobra.Command, args []string) {
			stt := args[0]
			common.CliRun(func(ctx context.Context, cli fgs.FineGuidanceSensorsClient) {
				sttPrint(ctx, cli, stt)
			})
		},
	}
	sttCmd.AddCommand(sttPrintCmd)

	return sttCmd
}

func sttPrint(ctx context.Context, client fgs.FineGuidanceSensorsClient, stt string) {
	res, err := client.GetStackTraceTree(ctx, &fgs.GetStackTraceTreeRequest{Name: stt})
	if err != nil {
		fmt.Printf("error printing stt %s: %s\n", stt, err)
		return
	}

	// NB: leave this here, in case we want to add a json option at some point
	if false {
		res_json, err := json.Marshal(res)
		if err != nil {
			fmt.Printf("error marshaling stt %s: %s\n", stt, err)
			return
		}
		fmt.Printf("%s\n", string(res_json))
	}

	sttPrintNodeTree(res.Root, 0)
}

func sttPrintNodeTree(node *fgs.StackTraceNode, level int) {
	indent_space := "    "
	indent := strings.Repeat(indent_space, level)
	fmt.Printf("%s0x%x (%s) count:%d\n", indent, node.Address.Address, node.Address.Symbol, node.Count)

	nchildren := len(node.Children)
	for _, child := range node.Children {
		sttPrintNodeTree(child, level+1)
	}

	// This is a leaf, so we also print label counters
	if nchildren == 0 {
		for _, label := range node.Labels {
			fmt.Printf("%s%s%s count:%d\n", indent, indent_space, label.Key, label.Count)
		}
	}
}
