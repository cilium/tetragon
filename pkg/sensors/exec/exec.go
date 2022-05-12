// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"

	"github.com/isovalent/tetragon-oss/pkg/api/ops"
	api "github.com/isovalent/tetragon-oss/pkg/api/processapi"
	"github.com/isovalent/tetragon-oss/pkg/bpf"
	"github.com/isovalent/tetragon-oss/pkg/btf"
	"github.com/isovalent/tetragon-oss/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/tetragon-oss/pkg/observer"
	"github.com/isovalent/tetragon-oss/pkg/sensors"
	"github.com/isovalent/tetragon-oss/pkg/sensors/exec/procevents"
)

func fromCString(cstr []byte) string {
	for i, c := range cstr {
		if c == 0 {
			return string(cstr[:i])
		}
	}
	return string(cstr)
}

func msgToExecveUnix(m *api.MsgExecveEvent) *api.MsgExecveEventUnix {
	unix := &api.MsgExecveEventUnix{}

	unix.Common = m.Common
	unix.Kube.NetNS = m.Kube.NetNS
	unix.Kube.Cid = m.Kube.Cid
	unix.Kube.Cgrpid = m.Kube.Cgrpid
	// The first byte is set to zero if there is no docker ID for this event.
	if m.Kube.Docker[0] != 0x00 {
		// We always get a null terminated buffer from bpf
		cgroup := fromCString(m.Kube.Docker[:api.DOCKER_ID_LENGTH])
		unix.Kube.Docker, _ = procevents.LookupContainerId(cgroup, true, false)
	}
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

func execParse(reader *bytes.Reader) (api.MsgProcess, bool, error) {
	proc := api.MsgProcess{}
	exec := api.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		fmt.Printf("read error!\n")
		return proc, true, err
	}

	proc.Size = exec.Size
	proc.PID = exec.PID
	proc.NSPID = exec.NSPID
	proc.UID = exec.UID
	proc.Flags = exec.Flags
	proc.Ktime = exec.Ktime
	proc.AUID = exec.AUID

	size := exec.Size - api.MSG_SIZEOF_EXECVE
	if size > api.MSG_SIZEOF_BUFFER-api.MSG_SIZEOF_EXECVE {
		err := fmt.Errorf("msg exec size larger than argsbuffer")
		exec.Size = api.MSG_SIZEOF_EXECVE
		proc.Args = "enomem enomem"
		proc.Filename = "enomem"
		return proc, false, err
	}

	args := make([]byte, size) //+2)
	if err := binary.Read(reader, binary.LittleEndian, &args); err != nil {
		proc.Size = api.MSG_SIZEOF_EXECVE
		proc.Args = "enomem enomem"
		proc.Filename = "enomem"
		return proc, false, err
	}

	cmdArgs := bytes.Split(args, []byte{0x00})
	proc.Filename = string(cmdArgs[0])
	proc.Args = string(bytes.Join(cmdArgs[1:], []byte{0x00}))

	return proc, false, nil
}

func nopMsgProcess() api.MsgProcess {
	return api.MsgProcess{
		Filename: "<enomem>",
		Args:     "<enomem>",
	}
}

func handleExecve(r *bytes.Reader) ([]observer.Event, error) {
	var empty bool

	m := api.MsgExecveEvent{}
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

func msgToExitUnix(m *api.MsgExitEvent) *api.MsgExitEventUnix {
	return m
}

func handleExit(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgExitEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExitUnix(&m)
	return []observer.Event{msgUnix}, nil
}

type execSensor struct {
	name string
}

func (e *execSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	btfObj := uintptr(btf.GetCachedBTF())

	i, err := bpf.LoadTracingProgram(
		args.Version,
		args.Verbose,
		btfObj,
		args.Load.Name,
		args.Load.Attach,
		args.Load.Label,
		filepath.Join(args.BPFDir, args.Load.PinPath),
		args.MapDir,
	)
	if err == nil {
		procevents.GetRunningProcs(true, true)
	}
	return i, err
}

func (e *execSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
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
}
