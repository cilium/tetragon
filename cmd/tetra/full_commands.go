// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !standalone

package main

import (
	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/dump"
	"github.com/cilium/tetragon/cmd/tetra/getevents"
	"github.com/cilium/tetragon/cmd/tetra/rthooks"
	"github.com/cilium/tetragon/cmd/tetra/sensors"
	"github.com/cilium/tetragon/cmd/tetra/stacktracetree"
	"github.com/cilium/tetragon/cmd/tetra/status"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	"github.com/cilium/tetragon/cmd/tetra/version"
	"github.com/spf13/cobra"
)

func addCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(getevents.New())
	rootCmd.AddCommand(version.New())
	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(sensors.New())
	rootCmd.AddCommand(stacktracetree.New())
	rootCmd.AddCommand(status.New())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(rthooks.New())
	rootCmd.AddCommand(dump.New())
}
