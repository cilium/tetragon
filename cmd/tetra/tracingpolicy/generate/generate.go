// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package generate

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/ftrace"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {

	var matchBinary string
	var regex string

	cmd := &cobra.Command{
		Use:   "generate <all-syscalls|all-syscalls-list|ftrace-list|empty>",
		Short: "generate tracing policies",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generateTracingPolicy(args[0], matchBinary, regex)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&matchBinary, "match-binary", "m", "", "Add binary to matchBinaries selector")
	flags.StringVarP(&regex, "regex", "r", "", "Use regex to limit the generated symbols")

	return cmd
}

func generateTracingPolicy(cmd, binary, regex string) {
	switch cmd {
	case "all-syscalls":
		generateAllSyscalls(binary)
	case "all-syscalls-list":
		generateAllSyscallsList(binary)
	case "ftrace-list":
		generateFtrace(binary, regex)
	case "empty":
		generateEmpty()
	}
}

func generateAllSyscalls(binary string) {
	crd, err := btf.GetSyscallsYaml(binary)
	if err != nil {
		fmt.Print(err)
		return
	}
	fmt.Printf("%s\n", crd)
}

func generateAllSyscallsList(binary string) {
	crd, err := btf.GetSyscallsYamlList(binary)
	if err != nil {
		fmt.Print(err)
		return
	}
	fmt.Printf("%s\n", crd)
}

func generateFtrace(binary, regex string) {
	syms, err := ftrace.ReadAvailFuncs(regex)
	if err != nil {
		logger.GetLogger().WithError(err).Fatalf("failed to read ftrace functions: %s", err)
	}

	crd := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "ftrace"
spec:
  lists:
  - name: "ftrace"
    values:`

	for idx := range syms {
		crd = crd + "\n" + fmt.Sprintf("    - \"%s\"", syms[idx])
	}

	crd = crd + `
  kprobes:
    - call: "list:ftrace"`

	if binary != "" {
		filter := `
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + binary + `"`

		crd = crd + filter
	}

	fmt.Printf("%s\n", crd)
}

func generateEmpty() {
	crd := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "empty" `

	fmt.Printf("%s\n", crd)
}
