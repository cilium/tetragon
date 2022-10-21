// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/data"
	exec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/sirupsen/logrus"
)

var (
	sensorCounter uint64
)

func fromCString(cstr []byte) string {
	for i, c := range cstr {
		if c == 0 {
			return string(cstr[:i])
		}
	}
	return string(cstr)
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

	unix.CleanupProcess = m.CleanupProcess

	return unix
}

func msgToExecveKubeUnix(m *processapi.MsgExecveEvent, exec_id string, filename string) processapi.MsgK8sUnix {
	kube := processapi.MsgK8sUnix{
		NetNS:  m.Kube.NetNS,
		Cid:    m.Kube.Cid,
		Cgrpid: m.Kube.Cgrpid,
	}

	// The first byte is set to zero if there is no docker ID for this event.
	if m.Kube.Docker[0] != 0x00 {
		// We always get a null terminated buffer from bpf
		cgroup := fromCString(m.Kube.Docker[:processapi.DOCKER_ID_LENGTH])
		docker, _ := procevents.LookupContainerId(cgroup, true, false)
		if docker != "" {
			kube.Docker = docker
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.id":       kube.Cgrpid,
				"cgroup.name":     cgroup,
				"docker":          kube.Docker,
				"process.exec_id": exec_id,
				"process.binary":  filename,
			}).Trace("process_exec: container ID set successfully")
		} else {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.id":       kube.Cgrpid,
				"cgroup.name":     cgroup,
				"process.exec_id": exec_id,
				"process.binary":  filename,
			}).Trace("process_exec: no container ID due to cgroup name not being a compatible ID, ignoring.")
		}
	} else {
		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.id":       kube.Cgrpid,
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
	proc.NSPID = exec.NSPID
	proc.UID = exec.UID
	proc.Flags = exec.Flags
	proc.Ktime = exec.Ktime
	proc.AUID = exec.AUID
	proc.Inode = exec.Inode
	proc.Digest = fmt.Sprintf("0x%x", exec.Digest[:32])

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

type execSensor struct {
	name string
}

func (e *execSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := program.LoadRawTracepointProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	if err == nil {
		procevents.GetRunningProcs()
	}
	return err
}

func createExecAllowList(name string, s []v1alpha1.ExecSpec) (*sensors.Sensor, error) {
	for i, allow := range s {
		fmt.Printf("%d: namespace %s allow id %s parent %s\n", i, allow.Namespace, allow.IdDigest, allow.ParentDigest)
		writeAllowPolicy(allow.Namespace, allow.IdDigest, allow.ParentDigest)

		pods := process.FindNamespace(allow.Namespace)
		if len(pods) > 0 {
			fmt.Printf("FindNamespace(%s): pods %v\n", 
			allow.Namespace, pods);
			containerIds, err := watcher.GetPodIds(pods)
			if err != nil {
				fmt.Printf("GetPodIds error %s\n", err)
				return nil, nil
			}
			for i, id := range containerIds {
				var b [128]byte
				fmt.Printf("enable %d/%d containerId %s\n", i, len(containerIds), id)
				for i := 0; i < len(id) && i < 128; i++ {
					b[i] = id[i];
				}
				enableNs(b, uint32(1))
			}
		}
	}
	return nil, nil
}

func (e *execSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec, ok := raw.(*v1alpha1.TracingPolicySpec)
	if !ok {
		s, ok := reflect.Indirect(reflect.ValueOf(raw)).FieldByName("TracingPolicySpec").Interface().(v1alpha1.TracingPolicySpec)
		if !ok {
			return nil, nil
		}
		spec = &s
	}
	name := fmt.Sprintf("exec-sensor-%d", atomic.AddUint64(&sensorCounter, 1))

	if len(spec.ExecAllow) > 0 {
		return createExecAllowList(name, spec.ExecAllow)
	}
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
	sensors.RegisterTracingSensorsAtInit("execve", execveProbe)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXECVE, handleExecve)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXIT, handleExit)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_CLONE, handleClone)
}
