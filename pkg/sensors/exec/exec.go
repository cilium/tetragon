// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/data"
	exec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/cgroup/cgrouptrackmap"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func standarizeContainerId(id string) string {
	if strings.HasSuffix(id, "service") {
		return ""
	}

	if len(id) > procevents.BpfContainerIdLength {
		return id[:procevents.BpfContainerIdLength]
	}

	return id
}

// Old container ID uses DOCKER_ID_LENGTH as it can be full path with cgroup subdirs
func oldContainerId(cstr []byte) string {
	// The first byte is set to zero if there is no docker ID for this event.
	if cstr[0] != 0x00 {
		// We always get a null terminated buffer from bpf
		cgroup := cgroups.CgroupNameFromCStr(cstr[:processapi.DOCKER_ID_LENGTH])
		container, _ := procevents.LookupContainerId(cgroup, true, false)
		logger.GetLogger().Debugf("Cgroup Tracking data unavailable falling back to containerID='%s'", container)
		return standarizeContainerId(container)
	}

	return ""
}

// This function handles both old and new behavior how we lookup for container ID
// If we can't find it using the new way we fallback to the old method
func containerIdFromCgrpId(m *processapi.MsgExecveEvent) string {
	id := m.Kube.Cgrpid
	configMap := base.CgroupsTrackingMap
	mapPath := filepath.Join(bpf.MapPrefixPath(), configMap.Name)

	if id == 0 {
		return oldContainerId(m.Kube.Docker[:])
	}

	cgrp, err := cgrouptrackmap.LookupCgroupTracker(mapPath, m.Kube.Cgrpid)
	if err != nil {
		logger.GetLogger().WithError(err).Debugf("Failed to lookup Cgroup Tracking data for CgroupId=%d", id)
		return oldContainerId(m.Kube.Docker[:])
	}

	name := cgroups.CgroupNameFromCStr(cgrp.Name[:255])
	if name == "" {
		logger.GetLogger().Debugf("Failed to lookup Cgroup Name for CgroupId=%d", id)
		return oldContainerId(m.Kube.Docker[:])
	}

	s, _ := procevents.ProcsContainerIdOffset(name)

	return standarizeContainerId(s)
}

func msgToExecveUnix(m *processapi.MsgExecveEvent) *exec.MsgExecveEventUnix {
	unix := &exec.MsgExecveEventUnix{}

	unix.Common = m.Common
	unix.Kube.NetNS = m.Kube.NetNS
	unix.Kube.Cid = m.Kube.Cid
	unix.Kube.Cgrpid = m.Kube.Cgrpid
	unix.Kube.Docker = containerIdFromCgrpId(m)
	unix.Parent = m.Parent
	unix.Capabilities = m.Capabilities

	unix.Namespaces.UtsInum = m.Namespaces.UtsInum
	unix.Namespaces.IpcInum = m.Namespaces.IpcInum
	unix.Namespaces.MntInum = m.Namespaces.MntInum
	unix.Namespaces.PidInum = m.Namespaces.PidInum
	unix.Namespaces.PidChildInum = m.Namespaces.PidChildInum
	unix.Namespaces.NetInum = m.Namespaces.NetInum
	unix.Namespaces.TimeInum = m.Namespaces.TimeInum
	unix.Namespaces.TimeChildInum = m.Namespaces.TimeChildInum
	unix.Namespaces.CgroupInum = m.Namespaces.CgroupInum
	unix.Namespaces.UserInum = m.Namespaces.UserInum

	return unix
}

func execParse(reader *bytes.Reader) (processapi.MsgProcess, bool, error) {
	proc := processapi.MsgProcess{}
	exec := processapi.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		logger.GetLogger().WithError(err).Debug("Failed to read exec event")
		return proc, true, err
	}

	proc.Size = exec.Size
	proc.PID = exec.PID
	proc.NSPID = exec.NSPID
	proc.UID = exec.UID
	proc.Flags = exec.Flags
	proc.Ktime = exec.Ktime
	proc.AUID = exec.AUID

	size := exec.Size - processapi.MSG_SIZEOF_EXECVE
	if size > processapi.MSG_SIZEOF_BUFFER-processapi.MSG_SIZEOF_EXECVE {
		err := fmt.Errorf("msg exec size larger than argsbuffer")
		exec.Size = processapi.MSG_SIZEOF_EXECVE
		proc.Args = "enomem enomem"
		proc.Filename = "enomem"
		return proc, false, err
	}

	args := make([]byte, size) //+2)
	if err := binary.Read(reader, binary.LittleEndian, &args); err != nil {
		proc.Size = processapi.MSG_SIZEOF_EXECVE
		proc.Args = "enomem enomem"
		proc.Filename = "enomem"
		return proc, false, err
	}

	if exec.Flags&api.EventDataFilename != 0 {
		var desc dataapi.DataEventDesc

		dr := bytes.NewReader(args)

		if err := binary.Read(dr, binary.LittleEndian, &desc); err != nil {
			proc.Size = processapi.MSG_SIZEOF_EXECVE
			proc.Args = "enomem enomem"
			proc.Filename = "enomem"
			return proc, false, err
		}
		data, err := data.Get(desc.Id)
		if err != nil {
			return proc, false, err
		}
		proc.Filename = string(data[:])
		args = args[unsafe.Sizeof(desc):]
	} else if exec.Flags&api.EventErrorFilename == 0 {
		n := bytes.Index(args, []byte{0x00})
		if n != -1 {
			proc.Filename = string(args[:n])
			args = args[n+1:]
		}
	}

	var cmdArgs [][]byte

	if exec.Flags&api.EventDataArgs != 0 {
		var desc dataapi.DataEventDesc

		dr := bytes.NewReader(args)

		if err := binary.Read(dr, binary.LittleEndian, &desc); err != nil {
			proc.Size = processapi.MSG_SIZEOF_EXECVE
			proc.Args = "enomem enomem"
			proc.Filename = "enomem"
			return proc, false, err
		}
		data, err := data.Get(desc.Id)
		if err != nil {
			return proc, false, err
		}
		// cut the zero byte
		if len(data) > 0 {
			n := len(data) - 1
			cmdArgs = bytes.Split(data[:n], []byte{0x00})
		}

		cwd := args[unsafe.Sizeof(desc):]
		cmdArgs = append(cmdArgs, cwd)
	} else {
		cmdArgs = bytes.Split(args, []byte{0x00})
	}

	proc.Args = string(bytes.Join(cmdArgs[0:], []byte{0x00}))
	return proc, false, nil
}

func nopMsgProcess() processapi.MsgProcess {
	return processapi.MsgProcess{
		Filename: "<enomem>",
		Args:     "<enomem>",
	}
}

func handleExecve(r *bytes.Reader) ([]observer.Event, error) {
	var empty bool

	m := processapi.MsgExecveEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExecveUnix(&m)
	msgUnix.Process, empty, err = execParse(r)
	if err != nil && empty {
		msgUnix.Process = nopMsgProcess()
	}
	return []observer.Event{msgUnix}, nil
}

func msgToExitUnix(m *processapi.MsgExitEvent) *exec.MsgExitEventUnix {
	return &exec.MsgExitEventUnix{MsgExitEvent: *m}
}

func handleExit(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgExitEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExitUnix(&m)
	return []observer.Event{msgUnix}, nil
}

func handleClone(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgCloneEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := &exec.MsgCloneEventUnix{MsgCloneEvent: m}
	return []observer.Event{msgUnix}, nil
}

func handleCgroupEvent(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgCgroupEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := &exec.MsgCgroupEventUnix{MsgCgroupEvent: m}
	return []observer.Event{msgUnix}, nil
}

type execSensor struct {
	name string
}

func (e *execSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := program.LoadTracepointProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	if err == nil {
		procevents.GetRunningProcs()
	}
	return err
}

func (e *execSensor) SpecHandler(spec interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

func init() {
	AddExec()
}

func AddExec() {
	execveProbe := &execSensor{
		name: "exec base sensor",
	}
	sensors.RegisterProbeType("execve", execveProbe)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXECVE, handleExecve)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXIT, handleExit)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_CLONE, handleClone)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_CGROUP, handleCgroupEvent)
}
