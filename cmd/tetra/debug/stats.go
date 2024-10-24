// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func NewEnableStatsCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "enable-stats",
		Short: "Enable BPF stats",
		Run: func(_ *cobra.Command, _ []string) {
			// Enable bpf stats
			stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
			if err != nil {
				log.Fatal(fmt.Errorf("failed to enable stats: %v", err))
			}
			defer stats.Close()

			for {
				time.Sleep(time.Hour)
			}
		},
	}

	return &cmd
}
