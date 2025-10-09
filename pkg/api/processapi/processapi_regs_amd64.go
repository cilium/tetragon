// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux

package processapi

const (
	UPROBE_REGS_MAX = 18
)

type UprobeRegs struct {
	Ass [UPROBE_REGS_MAX]RegAssignment
	Cnt uint32
	Pad uint32
}
