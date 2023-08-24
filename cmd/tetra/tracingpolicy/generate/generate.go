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

	empty := &cobra.Command{
		Use:   "empty",
		Short: "empty",
		Run: func(cmd *cobra.Command, _ []string) {
			generateEmpty()
		},
	}

	allSyscalls := &cobra.Command{
		Use:   "all-syscalls",
		Short: "all system calls",
		Run: func(cmd *cobra.Command, _ []string) {
			generateAllSyscalls(matchBinary)
		},
	}

	allSyscallsList := &cobra.Command{
		Use:   "all-syscalls-list",
		Short: "all system calls using a list",
		Run: func(cmd *cobra.Command, _ []string) {
			generateAllSyscallsList(matchBinary)
		},
	}

	var ftraceRegex string
	ftraceList := &cobra.Command{
		Use:   "ftrace-list",
		Short: "ftrace list",
		Run: func(cmd *cobra.Command, _ []string) {
			generateFtrace(matchBinary, ftraceRegex)
		},
	}
	ftraceFlags := ftraceList.Flags()
	ftraceFlags.StringVarP(&ftraceRegex, "regex", "r", "", "Use regex to limit the generated symbols")

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "generate tracing policies",
	}
	pflags := cmd.PersistentFlags()
	pflags.StringVarP(&matchBinary, "match-binary", "m", "", "Add binary to matchBinaries selector")

	cmd.AddCommand(empty, allSyscalls, allSyscallsList, ftraceList)
	return cmd
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
