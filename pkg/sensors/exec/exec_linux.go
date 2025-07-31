// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/cgroups"
	exec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/sensors/exec/userinfo"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
)

func msgToExecveUnix(m *processapi.MsgExecveEvent) *exec.MsgExecveEventUnix {
	unix := &exec.MsgExecveEventUnix{}
	unix.Unix = &processapi.MsgExecveEventUnix{}
	unix.Unix.Msg = m
	return unix
}

func msgToExecveKubeUnix(m *processapi.MsgExecveEvent, execID string, filename string) processapi.MsgK8sUnix {
	kube := processapi.MsgK8sUnix{
		Cgrpid:        m.Kube.Cgrpid,
		CgrpTrackerID: m.Kube.CgrpTrackerID,
	}

	// If cgidmap is enabled, resolve the container id using the cgroup id and the cgroup
	// tracker id.
	if option.Config.EnableCgIDmap {
		cgidmap.SetContainerID(&kube)
		return kube
	}

	// The first byte is set to zero if there is no docker ID for this event.
	if m.Kube.Docker[0] != 0x00 {
		// We always get a null terminated buffer from bpf
		cgroup := cgroups.CgroupNameFromCStr(m.Kube.Docker[:processapi.CGROUP_NAME_LENGTH])
		docker, _ := procevents.LookupContainerId(cgroup, true, false)
		if docker != "" {
			kube.Docker = docker
			logger.Trace(logger.GetLogger(), "process_exec: container ID set successfully",
				"cgroup.id", m.Kube.Cgrpid,
				"cgroup.name", cgroup,
				"docker", kube.Docker,
				"process.exec_id", execID,
				"process.binary", filename)
		} else {
			logger.Trace(logger.GetLogger(), "process_exec: no container ID due to cgroup name not being a compatible ID, ignoring.",
				"cgroup.id", m.Kube.Cgrpid,
				"cgroup.name", cgroup,
				"process.exec_id", execID,
				"process.binary", filename)
		}
	} else {
		logger.Trace(logger.GetLogger(), "process_exec: no container ID due to cgroup name being empty, ignoring.",
			"cgroup.id", m.Kube.Cgrpid,
			"process.exec_id", execID,
			"process.binary", filename)
	}

	return kube
}

func execParse(reader *bytes.Reader) (processapi.MsgProcess, error) {
	proc := processapi.MsgProcess{
		Filename: "<enomem>",
		Args:     "<enomem>",
		Size:     processapi.MSG_SIZEOF_EXECVE,
	}
	exec := processapi.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		logger.GetLogger().Debug("Failed to read exec event", logfields.Error, err)
		return proc, err
	}

	proc.PID = exec.PID
	proc.TID = exec.TID
	proc.NSPID = exec.NSPID
	proc.UID = exec.UID
	proc.Flags = exec.Flags
	proc.Ktime = exec.Ktime
	proc.AUID = exec.AUID
	proc.SecureExec = exec.SecureExec
	proc.Nlink = exec.Nlink
	proc.Ino = exec.Ino

	size := exec.Size - processapi.MSG_SIZEOF_EXECVE
	if size > processapi.MSG_SIZEOF_BUFFER-processapi.MSG_SIZEOF_EXECVE {
		err := errors.New("msg exec size larger than argsbuffer")
		return proc, err
	}

	if size != uint32(exec.SizePath+exec.SizeArgs+exec.SizeCwd+exec.SizeEnvs) {
		err := fmt.Errorf("msg exec size larger than argsbuffer, size %d != %d, SizePath %d, SizeArgs %d, SizeCwd %d, SizeEnvs %d",
			size, exec.SizePath+exec.SizeArgs+exec.SizeCwd, exec.SizePath, exec.SizeArgs, exec.SizeCwd, exec.SizeEnvs)
		return proc, err
	}

	readData := func(size uint16) ([]byte, error) {
		var desc dataapi.DataEventDesc

		if uint16(unsafe.Sizeof(desc)) != size {
			return nil, errors.New("msg exec mismatched size")
		}
		if err := binary.Read(reader, binary.LittleEndian, &desc); err != nil {
			return nil, err
		}
		return observer.DataGet(desc)
	}

	if exec.SizePath != 0 {
		if exec.Flags&api.EventDataFilename != 0 {
			data, err := readData(exec.SizePath)
			if err != nil {
				return proc, err
			}
			proc.Filename = strutils.UTF8FromBPFBytes(data[:])
		} else {
			path := make([]byte, exec.SizePath)

			if err := binary.Read(reader, binary.LittleEndian, &path); err != nil {
				return proc, err
			}
			proc.Filename = strutils.UTF8FromBPFBytes(path[:exec.SizePath])
		}
	}

	var cmdArgs [][]byte

	if exec.SizeArgs != 0 {
		if exec.Flags&api.EventDataArgs != 0 {
			data, err := readData(exec.SizeArgs)
			if err != nil {
				return proc, err
			}
			// cut the zero byte
			if len(data) > 0 {
				n := len(data) - 1
				cmdArgs = bytes.Split(data[:n], []byte{0x00})
			}
		} else {
			data := make([]byte, exec.SizeArgs)
			if err := binary.Read(reader, binary.LittleEndian, &data); err != nil {
				return proc, err
			}
			cmdArgs = bytes.Split(data[:exec.SizeArgs], []byte{0x00})
		}
	}

	if exec.SizeCwd != 0 {
		cwd := make([]byte, exec.SizeCwd)

		if err := binary.Read(reader, binary.LittleEndian, &cwd); err != nil {
			return proc, err
		}
		cmdArgs = append(cmdArgs, cwd)
	}

	if exec.SizeEnvs != 0 {
		var data []byte
		var err error

		if exec.Flags&api.EventDataEnvs != 0 {
			data, err = readData(exec.SizeEnvs)
			if err != nil {
				return proc, err
			}
			// cut the zero byte
			data = data[:len(data)-1]
		} else {
			data = make([]byte, exec.SizeEnvs)
			if err := binary.Read(reader, binary.LittleEndian, &data); err != nil {
				return proc, err
			}
		}

		for v := range bytes.SplitSeq(data, []byte{0}) {
			proc.Envs = append(proc.Envs, strutils.UTF8FromBPFBytes(v))
		}
	}

	proc.Size = exec.Size
	proc.Args = strutils.UTF8FromBPFBytes(bytes.Join(cmdArgs[0:], []byte{0x00}))
	return proc, nil
}

func handleExecve(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgExecveEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExecveUnix(&m)
	msgUnix.Unix.Process, err = execParse(r)
	if err == nil {
		err = userinfo.MsgToExecveAccountUnix(msgUnix.Unix)
		if err != nil {
			logger.Trace(logger.GetLogger(), "Resolving process uid to username record failed",
				logfields.Error, err,
				"process.pid", msgUnix.Unix.Process.PID,
				"process.binary", msgUnix.Unix.Process.Filename,
				"process.uid", msgUnix.Unix.Process.UID)
		}
	}
	msgUnix.Unix.Kube = msgToExecveKubeUnix(&m, process.GetExecID(&msgUnix.Unix.Process), msgUnix.Unix.Process.Filename)
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

func handleThrottleEvent(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgThrottleEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	cgrouprate.Check(&m.Kube, m.Common.Ktime)
	return nil, nil
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
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_CLONE, handleClone)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_CGROUP, handleCgroupEvent)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_THROTTLE, handleThrottleEvent)
}
