// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"bytes"
	"encoding/binary"
	"errors"
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

func msgToExecveKubeUnix(m *processapi.MsgExecveEvent, exec_id string, filename string) processapi.MsgK8sUnix {
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
				"process.exec_id", exec_id,
				"process.binary", filename)
		} else {
			logger.Trace(logger.GetLogger(), "process_exec: no container ID due to cgroup name not being a compatible ID, ignoring.",
				"cgroup.id", m.Kube.Cgrpid,
				"cgroup.name", cgroup,
				"process.exec_id", exec_id,
				"process.binary", filename)
		}
	} else {
		logger.Trace(logger.GetLogger(), "process_exec: no container ID due to cgroup name being empty, ignoring.",
			"cgroup.id", m.Kube.Cgrpid,
			"process.exec_id", exec_id,
			"process.binary", filename)
	}

	return kube
}

func execParse(reader *bytes.Reader) (processapi.MsgProcess, bool, error) {
	proc := processapi.MsgProcess{}
	exec := processapi.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		logger.GetLogger().Debug("Failed to read exec event", logfields.Error, err)
		return proc, true, err
	}

	proc.Size = exec.Size
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
		data, err := observer.DataGet(desc)
		if err != nil {
			return proc, false, err
		}
		proc.Filename = strutils.UTF8FromBPFBytes(data[:])
		args = args[unsafe.Sizeof(desc):]
	} else if exec.Flags&api.EventErrorFilename == 0 {
		n := bytes.Index(args, []byte{0x00})
		if n != -1 {
			proc.Filename = strutils.UTF8FromBPFBytes(args[:n])
			args = args[n+1:]
		} else {
			// Filename not null-terminated or buffer consumed
			proc.Filename = strutils.UTF8FromBPFBytes(args[:])
			args = nil
		}
	} else if exec.Flags&api.EventErrorFilename != 0 {
		// Filename read error - buffer content is unreliable
		args = nil
	}

	// At this point, 'args' holds the buffer containing [arguments_string]\0\0[environment_string]
	// or 'args' is nil if filename parsing consumed everything or an error occurred.

	var argsPayload []byte
	var envsPayload []byte

	if args != nil {
		// If args are offloaded, read DataEventDesc struct for args
		if exec.Flags&api.EventDataArgs != 0 && len(args) >= int(unsafe.Sizeof(dataapi.DataEventDesc{})) {
			argsPayload = args[:unsafe.Sizeof(dataapi.DataEventDesc{})]
			// The rest is the CWD and envs, possibly separated by delimiter
			remainder := args[unsafe.Sizeof(dataapi.DataEventDesc{}):]
			delimiter := []byte{0x00, 0x00}
			parts := bytes.SplitN(remainder, delimiter, 2)
			if len(parts) > 0 {
				argsPayload = append(argsPayload, parts[0]...)
			}
			if len(parts) > 1 {
				envsPayload = parts[1]
			}
		} else if exec.Flags&api.EventDataArgs == 0 {
			// Inline: split on delimiter
			delimiter := []byte{0x00, 0x00}
			parts := bytes.SplitN(args, delimiter, 2)
			if len(parts) > 0 {
				argsPayload = parts[0]
			}
			if len(parts) > 1 {
				envsPayload = parts[1]
			}
		}
	}

	if exec.Flags&api.EventDataEnvs != 0 && envsPayload != nil && len(envsPayload) >= int(unsafe.Sizeof(dataapi.DataEventDesc{})) {
		envsPayload = envsPayload[:unsafe.Sizeof(dataapi.DataEventDesc{})]
	}

	// Process arguments: maintain original null-separated format for ArgsDecoder compatibility
	if exec.Flags&api.EventDataArgs != 0 {
		// Arguments are stored in separate data event
		if argsPayload != nil && len(argsPayload) >= int(unsafe.Sizeof(dataapi.DataEventDesc{})) {
			var descArgs dataapi.DataEventDesc
			drArgs := bytes.NewReader(argsPayload)
			if err := binary.Read(drArgs, binary.LittleEndian, &descArgs); err != nil {
				proc.Args = "enomem args_data_event_desc_read_error"
			} else {
				actualArgsData, err := observer.DataGet(descArgs)
				if err != nil {
					proc.Args = "enomem args_data_event_get_error"
				} else {
					// Preserve original format: combine data event args with inline remainder
					restOfArgsPayload := argsPayload[unsafe.Sizeof(descArgs):]

					var combined []byte
					if len(actualArgsData) > 0 {
						combined = append(combined, actualArgsData...)
						if len(restOfArgsPayload) > 0 && len(combined) > 0 && combined[len(combined)-1] != 0x00 {
							combined = append(combined, 0x00)
						}
					}
					if len(restOfArgsPayload) > 0 {
						combined = append(combined, restOfArgsPayload...)
					}
					proc.Args = strutils.UTF8FromBPFBytes(combined)
				}
			}
		} else {
			proc.Args = ""
		}
	} else {
		// Arguments and CWD are inline in buffer
		if argsPayload != nil {
			proc.Args = strutils.UTF8FromBPFBytes(argsPayload)
		} else {
			proc.Args = ""
		}
	}

	// Process environment variables
	if exec.Flags&api.EventErrorEnvs != 0 {
		proc.Envs = "error reading envs"
	} else if exec.Flags&api.EventDataEnvs != 0 {
		// Environment variables stored in separate data event
		if envsPayload != nil && len(envsPayload) >= int(unsafe.Sizeof(dataapi.DataEventDesc{})) {
			var descEnvs dataapi.DataEventDesc
			drEnvs := bytes.NewReader(envsPayload)
			if err := binary.Read(drEnvs, binary.LittleEndian, &descEnvs); err != nil {
				proc.Envs = "error decoding envs descriptor"
			} else {
				actualEnvsData, err := observer.DataGet(descEnvs)
				if err != nil {
					proc.Envs = "error retrieving offband envs data"
				} else {
					d := actualEnvsData
					if len(d) > 0 && d[len(d)-1] == 0x00 {
						d = d[:len(d)-1]
					}
					proc.Envs = strutils.UTF8FromBPFBytes(bytes.ReplaceAll(d, []byte{0x00}, []byte{' '}))
				}
			}
		} else {
			proc.Envs = "envs descriptor missing or too short"
		}
	} else {
		// Environment variables are inline in buffer
		if envsPayload != nil {
			b := envsPayload
			if len(b) > 0 && b[len(b)-1] == 0x00 {
				b = b[:len(b)-1]
			}
			proc.Envs = strutils.UTF8FromBPFBytes(bytes.ReplaceAll(b, []byte{0x00}, []byte{' '}))
		} else {
			proc.Envs = ""
		}
	}

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
	msgUnix.Unix.Process, empty, err = execParse(r)
	if err != nil && empty {
		msgUnix.Unix.Process = nopMsgProcess()
	}
	if err == nil && !empty {
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
