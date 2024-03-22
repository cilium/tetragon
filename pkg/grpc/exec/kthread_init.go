// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

// This is used only when we add kernel threads during /proc scanning.
// We use the same interface with all the other events to make the handling
// of them easier.
type MsgKThreadInitUnix struct {
	Unix *processapi.MsgExecveEventUnix
}

func (msg *MsgKThreadInitUnix) HandleMessage() *tetragon.GetEventsResponse {
	proc := process.AddExecEvent(msg.Unix)
	parent, err := process.Get(proc.UnsafeGetProcess().ParentExecId)
	if err != nil {
		logger.GetLogger().Warnf("Failed to find parent for kernel thread %d", msg.Unix.Msg.Parent.Pid)
		return nil
	}
	parent.RefInc("parent")
	return nil
}

func (msg *MsgKThreadInitUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, nil
}

func (msg *MsgKThreadInitUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return nil
}

func (msg *MsgKThreadInitUnix) Notify() bool {
	return false
}

func (msg *MsgKThreadInitUnix) Cast(_ interface{}) notify.Message {
	return &MsgKThreadInitUnix{}
}
