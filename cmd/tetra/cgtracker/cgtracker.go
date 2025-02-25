// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgtracker

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/cgidarg"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "cgtracker",
		Short:        "manage cgtracker map (only for debugging)",
		Hidden:       true,
		SilenceUsage: true,
	}

	ret.AddCommand(
		dumpCmd(),
		addCommand(),
	)

	return ret
}

func dumpCmd() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, cgtracker.MapName)
	ret := &cobra.Command{
		Use:   "dump",
		Short: "dump cgtracker map state",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			m, err := cgtracker.OpenMap(mapFname)
			if err != nil {
				log.Fatal(err)
			}
			defer m.Close()

			vals, err := m.Dump()
			if err != nil {
				return err
			}
			for tracker, tracked := range vals {
				fmt.Printf("%d: %v\n", tracker, tracked)
			}
			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "cgtracker map filename")
	return ret
}

func addCommand() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, cgtracker.MapName)
	ret := &cobra.Command{
		Use:   "add cg_tracked cg_tracker",
		Short: "add cgtracker entry",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			tracked, err := cgidarg.Parse(args[0])
			if err != nil {
				return err
			}
			tracker, err := cgidarg.Parse(args[1])
			if err != nil {
				return err
			}
			m, err := cgtracker.OpenMap(mapFname)
			if err != nil {
				return err
			}
			defer m.Close()
			return m.Add(tracked, tracker)

		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "cgtracker map filename")
	return ret
}
