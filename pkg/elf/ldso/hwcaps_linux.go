// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ldso

// glibc >= 2.33 looks up libraries in the glibc-hwcaps subdirectories of
// every search directory first (e.g. /usr/lib64/glibc-hwcaps/x86-64-v3/),
// for each subdirectory supported by the CPU, in priority order. Distros use
// them to ship builds optimized for newer CPUs, so we need to pick the same
// build as ld.so does: offsets of symbols differ between them.
//
// The CPU is the one of the machine Tetragon runs on, which is shared with
// any process (and container) on it. Per-process overrides (the
// --glibc-hwcaps-prepend/--glibc-hwcaps-mask ld.so options, and the
// glibc.cpu.hwcaps tunable) are not taken into account.

// hostHwcaps returns the glibc-hwcaps subdirectories ld.so searches on this
// machine for a binary of the given ELF machine and class, in decreasing
// priority order. The implementation is architecture specific, see
// archHwcaps. It's a variable so that tests can override it.
var hostHwcaps = archHwcaps
