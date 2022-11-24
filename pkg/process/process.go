// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	hubble "github.com/cilium/hubble/pkg/cilium"

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

	hubblev1 "github.com/cilium/hubble/pkg/api/v1"
	corev1 "k8s.io/api/core/v1"
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

func InitCache(ctx context.Context, w watcher.K8sResourceWatcher, enableCilium bool, size int) error {
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

func (pi *ProcessInternal) GetProcessInternalCopy() *ProcessInternal {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	return &ProcessInternal{
		process:      proto.Clone(pi.process).(*tetragon.Process),
		capabilities: pi.capabilities,
		namespaces:   pi.namespaces,
		refcnt:       1,
	}
}

func (pi *ProcessInternal) AddPodInfo(pod *tetragon.Pod) {
	pi.mu.Lock()
	pi.process.Pod = pod
	pi.mu.Unlock()
}

func (pi *ProcessInternal) GetProcess() *tetragon.Process {
	pi.mu.Lock()
	return pi.process
}

func (pi *ProcessInternal) PutProcess() {
	pi.mu.Unlock()
}

func (pi *ProcessInternal) UnsafeGetProcess() *tetragon.Process {
	return pi.process
}

func (pi *ProcessInternal) AnnotateProcess(cred, ns bool) error {
	process := pi.GetProcess()
	defer pi.PutProcess()
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

func (pi *ProcessInternal) UnsafeGetProcessCap() *tetragon.Capabilities {
	return pi.capabilities
}

func (pi *ProcessInternal) RefDec() {
	procCache.refDec(pi)
}

func (pi *ProcessInternal) RefInc() {
	procCache.refInc(pi)
}

func (pi *ProcessInternal) RefGet() uint32 {
	ref := atomic.LoadUint32(&pi.refcnt)
	return ref
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

func GetProcess(
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

func FindPod(containerId string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	return k8s.FindPod(containerId)
}

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
		proc, _ = GetProcess(event.Process, event.Kube.Docker, event.Parent, event.Capabilities, event.Namespaces)
	} else {
		proc, _ = GetProcess(event.Process, event.Kube.Docker, event.CleanupProcess, event.Capabilities, event.Namespaces)
	}
	procCache.Add(proc)
	return proc
}

// AddCloneEvent adds a new process into the cache from a CloneEvent
func AddCloneEvent(event *tetragonAPI.MsgCloneEvent) error {
	parentExecId := GetProcessID(event.Parent.Pid, event.Parent.Ktime)
	parent, err := Get(parentExecId)
	if err != nil {
		logger.GetLogger().WithField("parent-exec-id", parentExecId).Debug("AddCloneEvent: process not found in cache")
		return err
	}
	parent.RefInc()
	pi := parent.GetProcessInternalCopy()
	if pi.process != nil {
		pi.process.ParentExecId = parentExecId
		pi.process.ExecId = GetProcessID(event.PID, event.Ktime)
		pi.process.Pid = &wrapperspb.UInt32Value{Value: event.PID}
		pi.process.Flags = strings.Join(exec.DecodeCommonFlags(event.Flags), " ")
		pi.process.StartTime = ktime.ToProto(event.Ktime)
		pi.process.Refcnt = 1
		if pi.process.Pod != nil && pi.process.Pod.Container != nil {
			pi.process.Pod.Container.Pid = &wrapperspb.UInt32Value{Value: event.NSPID}
		}
		if option.Config.EnableK8s && pi.process.Docker != "" && pi.process.Pod == nil {
			if podInfo, _ := GetPodInfo(pi.process.Docker, pi.process.Binary, pi.process.Arguments, event.NSPID); podInfo != nil {
				pi.AddPodInfo(podInfo)
			}
		}
		procCache.Add(pi)
	}
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
	pod, _, ok := FindPod(p.Docker)
	if !ok {
		logger.GetLogger().WithField("container id", p.Docker).Trace("failed to get pod")
		return nil
	}
	endpoint, _ := cilium.GetCiliumState().GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	return endpoint
}
