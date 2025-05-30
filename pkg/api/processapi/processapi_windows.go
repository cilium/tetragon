// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package processapi

type MsgCreateProcessEvent struct {
	Common            MsgCommon
	ProcessID         uint32
	ParentProcessID   uint32
	CreatingProcessID uint32
	CreatingThreadID  uint32
	UserLUID          uint64
	CreationTime      uint64
}

type MsgExitProcessEvent struct {
	Common          MsgCommon
	ProcessID       uint32
	ExitTime        uint64
	ProcessExitCode uint32
}
