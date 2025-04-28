// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package generate

import (
	"debug/elf"
	"errors"
	"log"
	"os"

	telf "github.com/cilium/tetragon/pkg/elf"
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
		Run: func(_ *cobra.Command, _ []string) {
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
		Run: func(_ *cobra.Command, _ []string) {
			tp := generate.NewTracingPolicy("syscalls")
			syscalls, err := AvailableSyscalls()
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
		Run: func(_ *cobra.Command, _ []string) {
			tp := generate.NewTracingPolicy("syscalls")
			syscalls, err := AvailableSyscalls()
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
		Run: func(_ *cobra.Command, _ []string) {
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

	var uprobesBinary string
	uprobes := &cobra.Command{
		Use:   "uprobes",
		Short: "all binary symbols",
		Run: func(_ *cobra.Command, _ []string) {
			if uprobesBinary == "" {
				log.Fatalf("binary is not specified, please use --binary option")
			}

			file, err := elf.Open(uprobesBinary)
			if err != nil {
				log.Fatalf("failed to open '%s': %v", uprobesBinary, err)
			}

			syms, err := file.Symbols()
			if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
				log.Fatalf("failed to get symtab for open '%s': %v", uprobesBinary, err)
			}

			dynsyms, err := file.DynamicSymbols()
			if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
				log.Fatalf("failed to get dynsym for open '%s': %v", uprobesBinary, err)
			}

			syms = append(syms, dynsyms...)

			tp := generate.NewTracingPolicy("uprobes")
			uprobe := generate.AddUprobe(tp)

			for _, sym := range syms {
				if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
					continue
				}
				if sym.Value == 0 {
					continue
				}
				uprobe.Symbols = append(uprobe.Symbols, sym.Name)
			}

			uprobe.Path = uprobesBinary
			b, err := yaml.Marshal(tp)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(b)
		},
	}

	uprobesFlags := uprobes.Flags()
	uprobesFlags.StringVarP(&uprobesBinary, "binary", "b", "", "Binary path")

	var usdtsBinary string
	usdts := &cobra.Command{
		Use:   "usdts",
		Short: "all usdts",
		Run: func(_ *cobra.Command, _ []string) {
			if usdtsBinary == "" {
				log.Fatalf("binary is not specified, please use --binary option")
			}

			se, err := telf.OpenSafeELFFile(usdtsBinary)
			if err != nil {
				log.Fatalf("failed to open '%s': %v", usdtsBinary, err)
			}

			tp := generate.NewTracingPolicy("usdts")
			usdt := generate.AddUsdt(tp)

			targets, err := se.UsdtTargets()
			if err != nil {
				log.Fatalf("failed to retrieve usdt targets '%s': %v", usdtsBinary, err)
			}

			for _, target := range targets {
				usdt.Provider = target.Spec.Provider
				usdt.Name = target.Spec.Name
			}

			usdt.Path = usdtsBinary
			b, err := yaml.Marshal(tp)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(b)
		},
	}

	usdtsFlags := usdts.Flags()
	usdtsFlags.StringVarP(&usdtsBinary, "binary", "b", "", "Binary path")

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "generate tracing policies",
	}
	pflags := cmd.PersistentFlags()
	pflags.StringVarP(&matchBinary, "match-binary", "m", "", "Add binary to matchBinaries selector")

	cmd.AddCommand(empty, allSyscalls, allSyscallsList, ftraceList, uprobes, usdts)
	return cmd
}
