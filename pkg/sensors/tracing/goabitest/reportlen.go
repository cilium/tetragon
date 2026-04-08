// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package goabitest holds tiny Go entrypoints used only by integration tests so
// cmd/goabi-gen can resolve ABIInternal register slots for uprobes.
package goabitest

import "os"

//go:noinline

// ReportLenForABI exits with len(s). Uprobe ClearGoString tests attach here:
// clearing the incoming string length register should make s appear empty at
// function entry, so the process should exit with code 0.
func ReportLenForABI(s string) {
	os.Exit(len(s))
}
