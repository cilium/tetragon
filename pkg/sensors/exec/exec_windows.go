// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	exec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/userinfo"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
)

func msgToExecveUnix(m *processapi.MsgCreateProcessEvent) *exec.MsgExecveEventUnix {
	unix := &exec.MsgExecveEventUnix{}
	unix.Unix = &processapi.MsgExecveEventUnix{}

	unix.Unix.Process = processapi.MsgProcess{
		PID:   m.ProcessID,
		TID:   m.ProcessID,
		NSPID: 0,
		UID:   uint32(m.UserLUID),
		Flags: 1,
		Size:  0,
		Ktime: m.CreationTime,
	}
	unix.Unix.Msg = &processapi.MsgExecveEvent{
		Common: m.Common,
		Kube:   processapi.MsgK8s{},
		Parent: processapi.MsgExecveKey{
			Pid:   m.CreatingProcessID,
			Ktime: 0,
		},
	}
	unix.Unix.Process.Filename, unix.Unix.Process.Args, _ = getArgsFromPID(m.ProcessID)
	unix.Unix.Process.Size = uint32(unsafe.Sizeof(unix.Unix.Process))
	unix.Unix.Process.Flags = api.EventNoCWDSupport
	return unix
}

func nopMsgProcess() processapi.MsgProcess {
	return processapi.MsgProcess{
		Filename: "<enomem>",
		Args:     "<enomem>",
	}
}

func handleExecve(r *bytes.Reader) ([]observer.Event, error) {
	var empty bool

	m := processapi.MsgCreateProcessEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExecveUnix(&m)
	if err != nil && empty {
		msgUnix.Unix.Process = nopMsgProcess()
	}
	if err == nil && !empty {
		err = userinfo.MsgToExecveAccountUnix(msgUnix.Unix)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"process.pid":    msgUnix.Unix.Process.PID,
				"process.binary": msgUnix.Unix.Process.Filename,
				"process.uid":    msgUnix.Unix.Process.UID,
			}).WithError(err).Trace("Resolving process uid to username record failed")
		}
	}
	return []observer.Event{msgUnix}, nil
}

func msgToExitUnix(m *processapi.MsgExitProcessEvent) *exec.MsgExitEventUnix {
	msgExitEvent := processapi.MsgExitEvent{
		Common: m.Common,
		ProcessKey: processapi.MsgExecveKey{
			Pid:   m.ProcessID,
			Ktime: m.Common.Ktime,
		},
		Info: processapi.MsgExitInfo{
			Code: m.ProcessExitCode,
			Tid:  m.ProcessID,
		},
	}
	return &exec.MsgExitEventUnix{MsgExitEvent: msgExitEvent}
}

func handleExit(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgExitProcessEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExitUnix(&m)
	return []observer.Event{msgUnix}, nil
}

type execProbe struct{}

func (e *execProbe) LoadProbe(args sensors.LoadProbeArgs) error {
	return program.LoadTracepointProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
}

func init() {
	AddExec()
}

func AddExec() {
	sensors.RegisterProbeType("execve", &execProbe{})

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXECVE, handleExecve)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXIT, handleExit)
}
