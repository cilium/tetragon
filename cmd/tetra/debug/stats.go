// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package debug

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func NewEnableStatsCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "enable-stats",
		Short: "Enable BPF stats",
		RunE: func(_ *cobra.Command, _ []string) error {
			// We enable BPF stats system wide keep it enabled as long as
			// the stats descriptor is open - app is running
			_, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
			if err != nil {
				return fmt.Errorf("failed to enable stats: %v", err)
			}

			// BPF stats are enabled..

			for {
				time.Sleep(time.Hour)
			}
		},
	}

	return &cmd
}
