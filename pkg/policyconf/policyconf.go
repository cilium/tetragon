// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyconf

import "fmt"

type Mode uint8

const (
	InvalidMode Mode = Mode(^uint8(0))
	// NB: values below should match the ones in bpf/lib/policy_conf.h
	EnforceMode Mode = 0
	MonitorMode Mode = 1
)

func ParseMode(s string) (Mode, error) {
	switch s {
	case "enforce":
		return EnforceMode, nil
	case "monitor":
		return MonitorMode, nil
	}

	return InvalidMode, fmt.Errorf("invalid mode: %q", s)
}
