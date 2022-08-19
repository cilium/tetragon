// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
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
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/cgroup/cgrouptrackmap"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
)

var (
	logEmptyCgrpid sync.Once
)

// standarizeContainerId() Ensures the passed ID is container ID with 32 characters
func standarizeContainerId(id string) string {
	if strings.HasSuffix(id, "service") {
		return ""
	}

	if len(id) >= procevents.BpfContainerIdLength {
		return id[:procevents.BpfContainerIdLength]
	}

	return ""
}

// containerFromBpfCgroup() Get the Container ID from the current
// Cgroup Name returned by BPF, this operates on current cgroup context.
func containerFromBpfCgroup(m *processapi.MsgExecveEvent, exec_id string, filename string) string {
	cgrpid := m.Kube.Cgrpid

	/* The first byte is set to zero if there is no docker ID for this event. */
	if m.Kube.Docker[0] == 0x00 {
		/* This can happen for a couple of reasons:
		 * - Failed to read the cgroup name or maybe the cgroup hierarchy or controller
		 *   is not set properly and we failed to read it? This is a bug.
		 */
		fs := cgroups.GetCgroupFSMagic()
		mode := cgroups.GetDeploymentMode()
		cgroupMode := cgroups.GetCgroupMode()
		if cgrpid != 0 {
			/* Cgroup is deep nested below the Cgroup container tracking level, and its
			 * parent or ancestor was not properly tracked?
			 */
			logger.GetLogger().WithFields(logrus.Fields{
				"deployment.mode": cgroups.DeploymentCode(mode).String(),
				"cgroup.mode":     cgroupMode.String(),
				"cgroup.fs.magic": cgroups.CgroupFsMagicStr(fs),
				"cgroup.id":       cgrpid,
				"process.exec_id": exec_id,
				"process.binary":  filename,
			}).Trace("process_exec: lookup container ID from BPF current context failed. cgroup.name is empty, cgroup ancestor was not tracked and it is nested below the tracking cgroup level")
			return ""
		}
		logEmptyCgrpid.Do(func() {
			err := fmt.Errorf("cgroup.name is empty and cgroup.id is zero this should not happen")
			logger.GetLogger().WithFields(logrus.Fields{
				"deployment.mode": cgroups.DeploymentCode(mode).String(),
				"cgroup.mode":     cgroupMode.String(),
				"cgroup.fs.magic": cgroups.CgroupFsMagicStr(fs),
				"cgroup.id":       cgrpid,
				"process.exec_id": exec_id,
				"process.binary":  filename,
			}).WithError(err).Warn("process_exec: lookup container ID from BPF current context failed. Please see documentation on how to report your cgroup configuration")
		})
		return ""
	}

	// We always get a null terminated buffer from bpf
	cgroup := cgroups.CgroupNameFromCStr(m.Kube.Docker[:processapi.CGROUP_NAME_LENGTH])
	container, _ := procevents.LookupContainerId(cgroup, true, false)
	docker := standarizeContainerId(container)
	if container == "" || docker == "" {
		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.id":       cgrpid,
			"cgroup.name":     cgroup,
			"process.exec_id": exec_id,
			"process.binary":  filename,
		}).Trace("process_exec: lookup container ID from BPF current context failed, cgroup name is not a container compatible ID")
		return ""
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"cgroup.id":       cgrpid,
		"cgroup.name":     cgroup,
		"docker":          docker,
		"process.exec_id": exec_id,
		"process.binary":  filename,
	}).Trace("process_exec: lookup container ID from BPF current cgroup name succeeded")

	return docker
}

// containerIDFromTrackedCgrp() Get a container ID from Cgroup information
// that should be in the tracking cgroup BPF map.
// If it fails it logs the operation, returns empty string and a bool to
// indicate if it should fallsback to current BPF context.
func containerIDFromTrackedCgrp(m *processapi.MsgExecveEvent, exec_id string, filename string) (string, bool) {
	id := m.Kube.Cgrpid
	cgroupMap := base.GetCgroupsTrackingMap()
	mapPath := filepath.Join(bpf.MapPrefixPath(), cgroupMap.Name)

	if id == 0 {
		/* This should never happen:
		 * We failed to read the Cgroup ID maybe the cgroup hierarchy or
		 * controller is not set properly and we failed to detect it?
		 * This bug should be reported.
		 */
		logEmptyCgrpid.Do(func() {
			err := fmt.Errorf("cgroup.id is zero this should not happen")
			fs := cgroups.GetCgroupFSMagic()
			mode := cgroups.GetDeploymentMode()
			cgroupMode := cgroups.GetCgroupMode()
			logger.GetLogger().WithFields(logrus.Fields{
				"bpf-map":         cgroupMap.Name,
				"deployment.mode": cgroups.DeploymentCode(mode).String(),
				"cgroup.mode":     cgroupMode.String(),
				"cgroup.fs.magic": cgroups.CgroupFsMagicStr(fs),
				"cgroup.id":       id,
				"process.exec_id": exec_id,
				"process.binary":  filename,
			}).WithError(err).Warn("process_exec: lookup container ID from Cgroups tracking map failed. Please see documentation on how to report your cgroup configuration")
		})
		/* Indicate we should retry as we failed to properly operate on
		 * on the cgroups hierarchy...
		 */
		return "", true
	}

	cgrp, err := cgrouptrackmap.LookupCgroupTracker(mapPath, id)
	if err != nil {
		/* Failed to read Cgroup tracked data from cgroup BPF map. */
		logger.GetLogger().WithFields(logrus.Fields{
			"bpf-map":         cgroupMap.Name,
			"cgroup.id":       id,
			"process.exec_id": exec_id,
			"process.binary":  filename,
		}).WithError(err).Trace("process_exec: lookup container ID from Cgroups tracking map failed, cgroup.id is not being tracked in the cgroups tracking BPF map")
		return "", true
	}

	cgroupName := cgroups.CgroupNameFromCStr(cgrp.Name[:processapi.CGROUP_NAME_LENGTH])
	if cgroupName == "" {
		/* This may happen if we have tracked the Cgroup ID but did not
		 * push the cgroup name to the tracking cgroup bpf map, maybe the
		 * process was running before tetragon? or there was a race somewhere?
		 */
		err := fmt.Errorf("tracked cgroup has an empty cgroup.name")
		logger.GetLogger().WithFields(logrus.Fields{
			"bpf-map":         cgroupMap.Name,
			"cgroup.id":       id,
			"process.exec_id": exec_id,
			"process.binary":  filename,
		}).WithError(err).Trace("process_exec: lookup container ID from Cgroups tracking map failed")
		return "", true
	}

	container, _ := procevents.LookupContainerId(cgroupName, false, false)
	docker := standarizeContainerId(container)
	if container == "" || docker == "" {
		logger.GetLogger().WithFields(logrus.Fields{
			"bpf-map":         cgroupMap.Name,
			"cgroup.id":       id,
			"cgroup.name":     cgroupName,
			"process.exec_id": exec_id,
			"process.binary":  filename,
		}).Trace("process_exec: lookup container ID from Cgroups tracking map failed, cgroup.name is not a container compatible ID")
		/* No need to retry here as the recorded cgroup name is not a container compatible ID */
		return "", false
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"bpf-map":         cgroupMap.Name,
		"cgroup.id":       id,
		"cgroup.name":     cgroupName,
		"docker":          docker,
		"process.exec_id": exec_id,
		"process.binary":  filename,
	}).Trace("process_exec: lookup container ID from Cgroups tracking map succeeded")

	return docker, false
}

func msgToExecveUnix(m *processapi.MsgExecveEvent) *exec.MsgExecveEventUnix {
	unix := &exec.MsgExecveEventUnix{}

	unix.Common = m.Common
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

func msgToExecveKubeUnix(m *processapi.MsgExecveEvent, exec_id string, filename string) processapi.MsgK8sUnix {
	kube := processapi.MsgK8sUnix{
		NetNS:  m.Kube.NetNS,
		Cid:    m.Kube.Cid,
		Cgrpid: m.Kube.Cgrpid,
	}

	/* First let's try the Cgroup tacking BPF map */
	docker, retry := containerIDFromTrackedCgrp(m, exec_id, filename)
	if docker == "" && retry == true {
		/* Fallback to current Cgroup context returned from BPF and
		 * log the operation that Cgroup Tracking data is unavailable.
		 */
		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.id":       kube.Cgrpid,
			"process.exec_id": exec_id,
			"process.binary":  filename,
		}).Trace("process_exec: lookup container ID from current BPF cgroup name as cgroups tracking data is unavailable")

		docker = containerFromBpfCgroup(m, exec_id, filename)
	}

	kube.Docker = docker

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
	msgUnix.Kube = msgToExecveKubeUnix(&m, process.GetExecID(&msgUnix.Process), msgUnix.Process.Filename)
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
