// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	hubble "github.com/cilium/tetragon/pkg/oldhubble/cilium"
	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/path"
	"github.com/cilium/tetragon/pkg/watcher"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	hubblev1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
)

// ProcessInternal is the internal representation of a process.
// nolint:revive // This is an acceptable case of "stuttering" since the name "Internal"
// wouldn't make much sense by itself.
type ProcessInternal struct {
	// mu protects the modifications to process.
	mu sync.Mutex
	// externally visible process struct.
	process *tetragon.Process
	// additional internal fields below
	capabilities *tetragon.Capabilities
	namespaces   *tetragon.Namespaces
	// garbage collector metadata
	color  int
	refcnt uint32
}

var (
	nodeName    string
	procCache   *Cache
	ciliumState *hubble.State
	k8s         watcher.K8sResourceWatcher
)

func InitCache(w watcher.K8sResourceWatcher, size int) error {
	var err error

	if procCache != nil {
		FreeCache()
	}

	nodeName = node.GetNodeNameForExport()
	ciliumState = cilium.GetCiliumState()
	if ciliumState == nil {
		return fmt.Errorf("ciliumState must be initialized before process cache")
	}
	k8s = w
	procCache, err = NewCache(size)
	if err != nil {
		k8s = nil
	}
	return err
}

func FreeCache() {
	procCache.Purge()
	procCache = nil
}

// GetProcessCopy() duplicates tetragon.Process and returns it
func (pi *ProcessInternal) GetProcessCopy() *tetragon.Process {
	if pi.process == nil {
		return nil
	}
	pi.mu.Lock()
	proc := proto.Clone(pi.process).(*tetragon.Process)
	pi.mu.Unlock()
	proc.Refcnt = atomic.LoadUint32(&pi.refcnt)
	return proc
}

// cloneInternalProcessCopy() duplicates ProcessInternal, sets its refcnt to 1
// and returns it
func (pi *ProcessInternal) cloneInternalProcessCopy() *ProcessInternal {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	return &ProcessInternal{
		process:      proto.Clone(pi.process).(*tetragon.Process),
		capabilities: pi.capabilities,
		namespaces:   pi.namespaces,
		refcnt:       1, // Explicitly initialize refcnt to 1
	}
}

func (pi *ProcessInternal) AddPodInfo(pod *tetragon.Pod) {
	pi.mu.Lock()
	pi.process.Pod = pod
	pi.mu.Unlock()
}

func (pi *ProcessInternal) getProcess() *tetragon.Process {
	pi.mu.Lock()
	return pi.process
}

func (pi *ProcessInternal) putProcess() {
	pi.mu.Unlock()
}

func (pi *ProcessInternal) UnsafeGetProcess() *tetragon.Process {
	return pi.process
}

func (pi *ProcessInternal) AnnotateProcess(cred, ns bool) error {
	process := pi.getProcess()
	defer pi.putProcess()
	if process == nil {
		return fmt.Errorf("Process is nil")
	}
	if cred {
		process.Cap = pi.capabilities
	}
	if ns {
		process.Ns = pi.namespaces
	}
	return nil
}

func (pi *ProcessInternal) RefDec() {
	procCache.refDec(pi)
}

func (pi *ProcessInternal) RefInc() {
	procCache.refInc(pi)
}

func (pi *ProcessInternal) RefGet() uint32 {
	return atomic.LoadUint32(&pi.refcnt)
}

// UpdateEventProcessTID Updates the Process.Tid of the event on the fly.
//
// From BPF side as we track processes by their TGID we do not cache TIDs,
// this is done on purpose since we only track clone and execve where
// TGID == TID, and also to simplify things. From user space perspective
// this works in general without any problem especially for execve events.
// A cached process (user space procCache) will always have its TGID == TID.
//
// However for other events we want to be precise and report the right
// thread that triggered an event. For such cases call this helper to
// set the Process.Tid to the corresponding thread ID that was reported
// from BPF side.
//
// There is no point on calling this helper on clone or execve events,
// however on all other events it is perfectly fine.
func UpdateEventProcessTid(process *tetragon.Process, tid *uint32) {
	if process != nil && tid != nil {
		process.Tid = &wrapperspb.UInt32Value{Value: *tid}
	}
}

func GetProcessID(pid uint32, ktime uint64) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", nodeName, ktime, pid)))
}

func GetExecID(proc *tetragonAPI.MsgProcess) string {
	return GetProcessID(proc.PID, proc.Ktime)
}

func GetExecIDFromKey(key *tetragonAPI.MsgExecveKey) string {
	return GetProcessID(key.Pid, key.Ktime)
}

// initProcessInternalExec() initialize and returns ProcessInternal and
// hubblev1.Endpoint objects from an execve event
func initProcessInternalExec(
	process tetragonAPI.MsgProcess,
	containerID string,
	parent tetragonAPI.MsgExecveKey,
	capabilities tetragonAPI.MsgCapabilities,
	namespaces tetragonAPI.MsgNamespaces,
) (*ProcessInternal, *hubblev1.Endpoint) {
	args, cwd := ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	if parent.Pid != 0 {
		parentExecID = GetExecIDFromKey(&parent)
	} else {
		parentExecID = GetProcessID(0, 1)
	}
	execID := GetExecID(&process)
	protoPod, endpoint := GetPodInfo(containerID, process.Filename, args, process.NSPID)
	caps := caps.GetMsgCapabilities(capabilities)
	ns := namespace.GetMsgNamespaces(namespaces)
	return &ProcessInternal{
		process: &tetragon.Process{
			Pid:          &wrapperspb.UInt32Value{Value: process.PID},
			Tid:          &wrapperspb.UInt32Value{Value: process.TID},
			Uid:          &wrapperspb.UInt32Value{Value: process.UID},
			Cwd:          cwd,
			Binary:       path.GetBinaryAbsolutePath(process.Filename, cwd),
			Arguments:    args,
			Flags:        strings.Join(exec.DecodeCommonFlags(process.Flags), " "),
			StartTime:    ktime.ToProtoOpt(process.Ktime, (process.Flags&api.EventProcFS) == 0),
			Auid:         &wrapperspb.UInt32Value{Value: process.AUID},
			Pod:          protoPod,
			ExecId:       execID,
			Docker:       containerID,
			ParentExecId: parentExecID,
			Refcnt:       0,
		},
		capabilities: caps,
		namespaces:   ns,
		refcnt:       1,
	}, endpoint
}

// initProcessInternalClone() initialize and returns ProcessInternal from
// a clone event
func initProcessInternalClone(event *tetragonAPI.MsgCloneEvent,
	parent *ProcessInternal, parentExecId string) (*ProcessInternal, error) {
	pi := parent.cloneInternalProcessCopy()
	if pi.process == nil {
		err := fmt.Errorf("failed to clone parent process from cache")
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":           "Clone",
			"event.parent.pid":     event.Parent.Pid,
			"event.parent.exec_id": parentExecId,
		}).WithError(err).Debug("CloneEvent: parent process information is missing")
		return nil, err
	}

	pi.process.ParentExecId = parentExecId
	pi.process.ExecId = GetProcessID(event.PID, event.Ktime)
	pi.process.Pid = &wrapperspb.UInt32Value{Value: event.PID}
	// Since from BPF side we only generate one clone event per
	// thread group that is for the leader, assert on that.
	if event.PID != event.TID {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Clone",
			"event.process.pid":     event.PID,
			"event.process.tid":     event.TID,
			"event.process.exec_id": pi.process.ExecId,
			"event.parent.exec_id":  parentExecId,
		}).Debug("CloneEvent: process PID and TID mismatch")
	}

	// This TID will be updated by the TID of the bpf execve event later,
	// so set it to zero here and ensure that it will be updated later.
	// Exported events must always be generated with a non zero TID.
	pi.process.Tid = &wrapperspb.UInt32Value{Value: 0}
	pi.process.Flags = strings.Join(exec.DecodeCommonFlags(event.Flags), " ")
	pi.process.StartTime = ktime.ToProto(event.Ktime)
	pi.process.Refcnt = 1
	if pi.process.Pod != nil && pi.process.Pod.Container != nil {
		// Set the pid inside the container
		pi.process.Pod.Container.Pid = &wrapperspb.UInt32Value{Value: event.NSPID}
	}
	if option.Config.EnableK8s && pi.process.Docker != "" && pi.process.Pod == nil {
		if podInfo, _ := GetPodInfo(pi.process.Docker, pi.process.Binary, pi.process.Arguments, event.NSPID); podInfo != nil {
			pi.AddPodInfo(podInfo)
		}
	}

	return pi, nil
}

// GetPodInfo() constructs and returns the Kubernetes Pod information associated with
// the Container ID and the PID inside this container.
func GetPodInfo(cid, bin, args string, nspid uint32) (*tetragon.Pod, *hubblev1.Endpoint) {
	return getPodInfo(k8s, cid, bin, args, nspid)
}

func GetParentProcessInternal(pid uint32, ktime uint64) (*ProcessInternal, *ProcessInternal) {
	var parent, process *ProcessInternal
	var err error

	processID := GetProcessID(pid, ktime)

	if process, err = procCache.get(processID); err != nil {
		logger.GetLogger().WithField("id in event", processID).WithField("pid", pid).WithField("ktime", ktime).Debug("process not found in cache")
		return nil, nil
	}

	if parent, err = procCache.get(process.process.ParentExecId); err != nil {
		logger.GetLogger().WithField("id in event", process.process.ParentExecId).WithField("pid", pid).WithField("ktime", ktime).Debug("parent process not found in cache")
		return process, nil
	}
	return process, parent
}

// AddExecEvent constructs a new ProcessInternal structure from an Execve event, adds it to the cache, and also returns it
func AddExecEvent(event *tetragonAPI.MsgExecveEventUnix) *ProcessInternal {
	var proc *ProcessInternal
	if event.CleanupProcess.Ktime == 0 || event.Process.Flags&api.EventClone != 0 {
		// there is a case where we cannot find this entry in execve_map
		// in that case we use as parent what Linux knows
		proc, _ = initProcessInternalExec(event.Process, event.Kube.Docker, event.Parent, event.Capabilities, event.Namespaces)
	} else {
		proc, _ = initProcessInternalExec(event.Process, event.Kube.Docker, event.CleanupProcess, event.Capabilities, event.Namespaces)
	}

	// Ensure that exported events have the TID set. For events from Kernel
	// we usually use PID == 0, so instead of checking against 0, assert that
	// TGID == TID
	if proc.process.Pid.GetValue() != proc.process.Tid.GetValue() {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Execve",
			"event.process.pid":     proc.process.Pid.GetValue(),
			"event.process.tid":     proc.process.Tid.GetValue(),
			"event.process.exec_id": proc.process.ExecId,
			"event.process.binary":  proc.process.Binary,
		}).Warn("ExecveEvent: process PID and TID mismatch")
	}

	procCache.add(proc)
	return proc
}

// AddCloneEvent adds a new process into the cache from a CloneEvent
func AddCloneEvent(event *tetragonAPI.MsgCloneEvent) error {
	parentExecId := GetProcessID(event.Parent.Pid, event.Parent.Ktime)
	parent, err := Get(parentExecId)
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":           "Clone",
			"event.parent.pid":     event.Parent.Pid,
			"event.parent.exec_id": parentExecId,
		}).WithError(err).Debug("CloneEvent: parent process not found in cache")
		return err
	}

	proc, err := initProcessInternalClone(event, parent, parentExecId)
	if err != nil {
		return err
	}

	parent.RefInc()
	procCache.add(proc)
	return nil
}

func Get(execId string) (*ProcessInternal, error) {
	return procCache.get(execId)
}

func GetProcessEndpoint(p *tetragon.Process) *hubblev1.Endpoint {
	if p == nil {
		return nil
	}
	if p.Docker == "" {
		return nil
	}
	pod, _, ok := k8s.FindContainer(p.Docker)
	if !ok {
		logger.GetLogger().WithField("container id", p.Docker).Trace("failed to get pod")
		return nil
	}
	endpoint, _ := cilium.GetCiliumState().GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	return endpoint
}
