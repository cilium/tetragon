// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package generate

import (
	"log"
	"os"

	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/ftrace"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy/generate"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

func New() *cobra.Command {

	var matchBinary string
	addSelectors := func(kprobe *v1alpha1.KProbeSpec) {
		if matchBinary != "" {
			sel := v1alpha1.KProbeSelector{
				MatchBinaries: []v1alpha1.BinarySelector{
					{
						Operator: "In",
						Values:   []string{matchBinary},
					},
				},
			}
			kprobe.Selectors = append(kprobe.Selectors, sel)
		}
	}

	empty := &cobra.Command{
		Use:   "empty",
		Short: "empty",
		Run: func(cmd *cobra.Command, _ []string) {
			tp := generate.NewTracingPolicy("empty")
			b, err := yaml.Marshal(tp)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(b)
		},
	}

	allSyscalls := &cobra.Command{
		Use:   "all-syscalls",
		Short: "all system calls",
		Run: func(cmd *cobra.Command, _ []string) {
			tp := generate.NewTracingPolicy("syscalls")
			syscalls, err := btf.AvailableSyscalls()
			if err != nil {
				log.Fatal(err)
			}
			for _, syscall := range syscalls {
				kprobe := generate.AddKprobe(tp)
				kprobe.Syscall = true
				kprobe.Call = syscall
				addSelectors(kprobe)
			}

			b, err := yaml.Marshal(tp)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(b)
		},
	}

	allSyscallsList := &cobra.Command{
		Use:   "all-syscalls-list",
		Short: "all system calls using a list",
		Run: func(cmd *cobra.Command, _ []string) {
			tp := generate.NewTracingPolicy("syscalls")
			syscalls, err := btf.AvailableSyscalls()
			if err != nil {
				log.Fatal(err)
			}
			tp.Spec.Lists = append(tp.Spec.Lists,
				v1alpha1.ListSpec{
					Name:   "syscalls",
					Type:   "syscalls",
					Values: syscalls,
				})
			kprobe := generate.AddKprobe(tp)
			kprobe.Call = "list:syscalls"
			kprobe.Syscall = true
			addSelectors(kprobe)
			b, err := yaml.Marshal(tp)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(b)
		},
	}

	var ftraceRegex string
	ftraceList := &cobra.Command{
		Use:   "ftrace-list",
		Short: "ftrace list",
		Run: func(cmd *cobra.Command, _ []string) {
			tp := generate.NewTracingPolicy("ftrace")
			syms, err := ftrace.ReadAvailFuncs(ftraceRegex)
			if err != nil {
				log.Fatal(err)
			}
			tp.Spec.Lists = append(tp.Spec.Lists,
				v1alpha1.ListSpec{
					Name:   "ftrace",
					Values: syms,
				})
			kprobe := generate.AddKprobe(tp)
			kprobe.Call = "list:ftrace"
			addSelectors(kprobe)
			b, err := yaml.Marshal(tp)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(b)
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
