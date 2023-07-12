// Copyright 2020-2021 Authors of Hubble
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

package bugtool

import (
	"github.com/cilium/tetragon/pkg/bugtool"

	"github.com/spf13/cobra"
)

var (
	outFile string
	bpfTool string
)

func New() *cobra.Command {
	bugtoolCmd := &cobra.Command{
		Use:   "bugtool",
		Short: "Produce a tar archive with debug information",
		Run: func(cmd *cobra.Command, args []string) {
			bugtool.Bugtool(outFile, bpfTool)
		},
	}

	flags := bugtoolCmd.Flags()
	flags.StringVarP(&outFile, "out", "o", "tetragon-bugtool.tar.gz", "Output filename")
	flags.StringVar(&bpfTool, "bpftool", "", "Path to bpftool binary")
	return bugtoolCmd
}
