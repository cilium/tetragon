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
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/sensors/exec/userinfo"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/sirupsen/logrus"
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
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.id":       m.Kube.Cgrpid,
				"cgroup.name":     cgroup,
				"docker":          kube.Docker,
				"process.exec_id": exec_id,
				"process.binary":  filename,
			}).Trace("process_exec: container ID set successfully")
		} else {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.id":       m.Kube.Cgrpid,
				"cgroup.name":     cgroup,
				"process.exec_id": exec_id,
				"process.binary":  filename,
			}).Trace("process_exec: no container ID due to cgroup name not being a compatible ID, ignoring.")
		}
	} else {
		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.id":       m.Kube.Cgrpid,
			"process.exec_id": exec_id,
			"process.binary":  filename,
		}).Trace("process_exec: no container ID due to cgroup name being empty, ignoring.")
	}

	return kube
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
			args = args[n+1:] // args is now the buffer after filename and its null terminator
		} else {
			// Filename not null-terminated, or buffer was empty after filename read attempt
			proc.Filename = strutils.UTF8FromBPFBytes(args[:]) // Take all if no null
			args = nil                                         // Consumed all for filename, so no args/envs to follow
		}
	} else if exec.Flags&api.EventErrorFilename != 0 {
		// Filename read error flag is set. proc.Filename might be empty or an error string.
		// The content of 'args' is uncertain. For safety, assume no reliable args/envs.
		// Alternatively, one might try to parse 'args' if BPF guarantees payload structure despite filename error.
		// For now, if EventErrorFilename is set, we won't attempt to parse args/envs from this buffer.
		args = nil
	}

	// At this point, 'args' holds the buffer containing [arguments_string]\0\0[environment_string]
	// or 'args' is nil if filename parsing consumed everything or an error occurred.

	var argsPayload []byte
	var envsPayload []byte

	if args != nil {
		delimiter := []byte{0x00, 0x00}
		parts := bytes.SplitN(args, delimiter, 2)

		if len(parts) > 0 {
			argsPayload = parts[0]
		}
		if len(parts) > 1 {
			envsPayload = parts[1]
		}
	}

	// Process argsPayload for proc.Args
	// This payload includes what was previously considered arguments and CWD.
	if exec.Flags&api.EventDataArgs != 0 {
		// Actual arguments are in a data event; argsPayload starts with its descriptor.
		// Any data in argsPayload after the descriptor is part of the CWD/args block.
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
					// The rest of argsPayload after the descriptor.
					restOfArgsPayload := argsPayload[unsafe.Sizeof(descArgs):]

					var combinedArgsComponents [][]byte
					if len(actualArgsData) > 0 {
						// Remove trailing null if present before splitting
						d := actualArgsData
						if d[len(d)-1] == 0x00 {
							d = d[:len(d)-1]
						}
						combinedArgsComponents = append(combinedArgsComponents, bytes.Split(d, []byte{0x00})...)
					}
					if len(restOfArgsPayload) > 0 {
						// Remove trailing null if present before splitting
						c := restOfArgsPayload
						if c[len(c)-1] == 0x00 {
							c = c[:len(c)-1]
						}
						combinedArgsComponents = append(combinedArgsComponents, bytes.Split(c, []byte{0x00})...)
					}
					proc.Args = strutils.UTF8FromBPFBytes(bytes.Join(combinedArgsComponents, []byte{' '}))
				}
			}
		} else {
			// argsPayload is nil or too short for a descriptor.
			proc.Args = ""
		}
	} else {
		// Arguments (including CWD) are inline in argsPayload.
		if argsPayload != nil {
			// Remove trailing null if present.
			b := argsPayload
			if len(b) > 0 && b[len(b)-1] == 0x00 {
				b = b[:len(b)-1]
			}
			proc.Args = strutils.UTF8FromBPFBytes(bytes.ReplaceAll(b, []byte{0x00}, []byte{' '}))
		} else {
			proc.Args = ""
		}
	}

	// Process envsPayload for proc.Envs
	if exec.Flags&api.EventErrorEnvs != 0 {
		proc.Envs = "error reading envs"
		// Consider setting proc.Environment = nil or an error marker if it's used
	} else if exec.Flags&api.EventDataEnvs != 0 {
		// Environment variables are in a separate event (data_event)
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
					// actualEnvsData is null-separated, potentially with a trailing null.
					d := actualEnvsData
					if len(d) > 0 && d[len(d)-1] == 0x00 {
						d = d[:len(d)-1] // Remove trailing null
					}
					proc.Envs = strutils.UTF8FromBPFBytes(bytes.ReplaceAll(d, []byte{0x00}, []byte{' '}))
					// To populate proc.Environment with a slice of strings:
					// if len(d) > 0 {
					// 	proc.Environment = strings.Split(string(d), "\x00")
					// } else {
					// 	proc.Environment = nil
					// }
				}
			}
		} else {
			proc.Envs = "envs descriptor missing or too short"
		}
	} else {
		// Inline environment variables
		if envsPayload != nil {
			b := envsPayload
			// BPF prepends \0\0. Strip these first.
			if len(b) >= 2 && b[0] == 0x00 && b[1] == 0x00 {
				b = b[2:]
			} else if len(b) > 0 && b[0] == 0x00 { // Handle cases like single leading null if b[1] was stripped by prev logic
				b = b[1:]
			}

			// Strip overall trailing null if it's the absolute end of the envs data.
			if len(b) > 0 && b[len(b)-1] == 0x00 {
				b = b[:len(b)-1]
			}

			proc.Envs = strutils.UTF8FromBPFBytes(bytes.ReplaceAll(b, []byte{0x00}, []byte{' '}))
			// To populate proc.Environment with a slice of strings:
			// if len(b) > 0 {
			// 	proc.Environment = strings.Split(string(b), "\x00")
			// } else {
			// 	proc.Environment = nil
			// }
		} else {
			proc.Envs = ""
			// proc.Environment = nil
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
			logger.GetLogger().WithFields(logrus.Fields{
				"process.pid":    msgUnix.Unix.Process.PID,
				"process.binary": msgUnix.Unix.Process.Filename,
				"process.uid":    msgUnix.Unix.Process.UID,
			}).WithError(err).Trace("Resolving process uid to username record failed")
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
