// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ldso

import (
	"debug/elf"

	"golang.org/x/sys/cpu"
)

// x86Feature is a set of the CPU features glibc checks to determine the
// supported x86-64 ISA levels, see glibc's sysdeps/x86/get-isa-level.h.
type x86Feature uint64

const (
	// x86-64-v2
	x86CX16 x86Feature = 1 << iota
	x86LAHF
	x86POPCNT
	x86SSE3
	x86SSE41
	x86SSE42
	x86SSSE3
	// x86-64-v3
	x86AVX
	x86AVX2
	x86BMI1
	x86BMI2
	x86F16C
	x86FMA
	x86LZCNT
	x86MOVBE
	x86OSXSAVE
	// x86-64-v4
	x86AVX512F
	x86AVX512BW
	x86AVX512CD
	x86AVX512DQ
	x86AVX512VL
)

// Features required by each x86-64 ISA level, each one including the
// previous.
const (
	x86V2 = x86CX16 | x86LAHF | x86POPCNT | x86SSE3 | x86SSE41 | x86SSE42 | x86SSSE3
	x86V3 = x86V2 | x86AVX | x86AVX2 | x86BMI1 | x86BMI2 | x86F16C | x86FMA | x86LZCNT | x86MOVBE | x86OSXSAVE
	x86V4 = x86V3 | x86AVX512F | x86AVX512BW | x86AVX512CD | x86AVX512DQ | x86AVX512VL
)

// x86Levels maps x86-64 ISA levels to their glibc-hwcaps subdirectory, in
// decreasing priority order.
var x86Levels = []struct {
	subdir string
	mask   x86Feature
}{
	{subdir: "x86-64-v4", mask: x86V4},
	{subdir: "x86-64-v3", mask: x86V3},
	{subdir: "x86-64-v2", mask: x86V2},
}

// x86HostFeatures maps each feature to the x/sys/cpu flag reporting it. Like
// glibc, x/sys/cpu relies on CPUID, and only reports AVX and AVX-512 features
// if the OS enabled their state saving.
var x86HostFeatures = []struct {
	feature x86Feature
	has     *bool
}{
	{x86CX16, &cpu.X86.HasCX16},
	{x86LAHF, &cpu.X86.HasLAHF},
	{x86POPCNT, &cpu.X86.HasPOPCNT},
	{x86SSE3, &cpu.X86.HasSSE3},
	{x86SSE41, &cpu.X86.HasSSE41},
	{x86SSE42, &cpu.X86.HasSSE42},
	{x86SSSE3, &cpu.X86.HasSSSE3},
	{x86AVX, &cpu.X86.HasAVX},
	{x86AVX2, &cpu.X86.HasAVX2},
	{x86BMI1, &cpu.X86.HasBMI1},
	{x86BMI2, &cpu.X86.HasBMI2},
	{x86F16C, &cpu.X86.HasF16C},
	{x86FMA, &cpu.X86.HasFMA},
	{x86LZCNT, &cpu.X86.HasLZCNT},
	{x86MOVBE, &cpu.X86.HasMOVBE},
	{x86OSXSAVE, &cpu.X86.HasOSXSAVE},
	{x86AVX512F, &cpu.X86.HasAVX512F},
	{x86AVX512BW, &cpu.X86.HasAVX512BW},
	{x86AVX512CD, &cpu.X86.HasAVX512CD},
	{x86AVX512DQ, &cpu.X86.HasAVX512DQ},
	{x86AVX512VL, &cpu.X86.HasAVX512VL},
}

// x86HwcapsSubdirs returns the x86-64 glibc-hwcaps subdirectories supported
// by a CPU with the given features, in decreasing priority order.
func x86HwcapsSubdirs(features x86Feature) []string {
	var subdirs []string
	for _, l := range x86Levels {
		if features&l.mask == l.mask {
			subdirs = append(subdirs, l.subdir)
		}
	}
	return subdirs
}

// archHwcaps returns the x86-64 glibc-hwcaps subdirectories supported by the
// host CPU, for x86-64 binaries.
func archHwcaps(machine elf.Machine, class elf.Class) []string {
	// The traced binary may not be an x86-64 one even on an x86-64 host
	// (e.g. i386 or x32 binaries): the x86-64-vN subdirectories don't apply.
	if machine != elf.EM_X86_64 || class != elf.ELFCLASS64 {
		return nil
	}
	var features x86Feature
	for _, f := range x86HostFeatures {
		if *f.has {
			features |= f.feature
		}
	}
	return x86HwcapsSubdirs(features)
}
