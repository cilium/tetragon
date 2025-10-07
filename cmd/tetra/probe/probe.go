// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package probe

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/bpf"
)

func checkCapSysAdmin() (bool, error) {
	caps := unix.CapUserData{}
	err := unix.Capget(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &caps)
	if err != nil {
		return false, fmt.Errorf("error getting capabilities: %w", err)
	}
	return caps.Effective&(1<<unix.CAP_SYS_ADMIN) != 0, nil
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:   "probe",
		Short: "Probe for eBPF system features availability",
		Long:  "Probe detects whether the eBPF system features required by Tetragon are\navailable on the running kernel.\n",
		PreRun: func(cmd *cobra.Command, _ []string) {
			// Also checking against CAP_BPF and CAP_PERFMON requires more work
			// since they are stored beyond the 32 bits set. Checking
			// CAP_SYS_ADMIN should produce sufficient warning most of the time.
			if ok, err := checkCapSysAdmin(); err == nil && !ok {
				cmd.PrintErrln("warning: for accurate results, you may need to run as root and/or with sufficient capabilities.")
			}
		},
		Run: func(cmd *cobra.Command, _ []string) {
			//cmd.Printf("KRAVA %t\n", bpf.HasUprobeRegsChange())
			cmd.Println(strings.ReplaceAll(bpf.LogFeatures(), ", ", "\n"))
		},
	}

	cmd.AddCommand(NewConfigCmd())
	return &cmd
}
