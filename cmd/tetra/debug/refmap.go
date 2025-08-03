// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
)

func NewRefMapCmd() *cobra.Command {
	var path string

	cmd := cobra.Command{
		Use:   "refmap",
		Short: "refferenced maps per program from object",
		Long: `Retrieve refferenced maps per program from object.
Example:
  # tetra debug refmap --path ./bpf/objs/bpf_generic_kprobe.o
`,

		RunE: func(_ *cobra.Command, _ []string) error {
			spec, err := ebpf.LoadCollectionSpec(path)
			if err != nil {
				return fmt.Errorf("loading collection spec failed: %w", err)
			}

			idx := 0
			for _, prog := range spec.Programs {
				refMaps := make(map[string]bool)
				for _, inst := range prog.Instructions {
					if inst.Reference() != "" {
						refMaps[inst.Reference()] = true
					}
				}

				if idx != 0 {
					fmt.Printf("\n")
				}
				fmt.Printf("%s: ", prog.Name)
				for m := range refMaps {
					fmt.Printf("%s ", m)
				}
				idx++
			}
			fmt.Printf("\n")
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&path, "path", "", "Path of the bpf object file.")
	return &cmd
}
