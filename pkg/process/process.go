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

	"github.com/isovalent/tetragon-oss/api/v1/fgs"
	"github.com/isovalent/tetragon-oss/pkg/api"
	fgsAPI "github.com/isovalent/tetragon-oss/pkg/api/processapi"
	"github.com/isovalent/tetragon-oss/pkg/cilium"
	"github.com/isovalent/tetragon-oss/pkg/ktime"
	"github.com/isovalent/tetragon-oss/pkg/logger"
	"github.com/isovalent/tetragon-oss/pkg/metrics"
	"github.com/isovalent/tetragon-oss/pkg/reader/caps"
	"github.com/isovalent/tetragon-oss/pkg/reader/exec"
	"github.com/isovalent/tetragon-oss/pkg/reader/namespace"
	"github.com/isovalent/tetragon-oss/pkg/reader/node"
	"github.com/isovalent/tetragon-oss/pkg/reader/path"
	"github.com/isovalent/tetragon-oss/pkg/watcher"
	"github.com/sirupsen/logrus"
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
	process *fgs.Process
	// additional internal fields below
	capabilities *fgs.Capabilities
	namespaces   *fgs.Namespaces
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
		return nil
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

func (pi *ProcessInternal) GetProcessCopy() *fgs.Process {
	if pi.process == nil {
		return nil
	}
	pi.mu.Lock()
	proc := proto.Clone(pi.process).(*fgs.Process)
	pi.mu.Unlock()
	proc.Refcnt = atomic.LoadUint32(&pi.refcnt)
	return proc
}

func (pi *ProcessInternal) AddPodInfo(pod *fgs.Pod) {
	pi.mu.Lock()
	pi.process.Pod = pod
	pi.mu.Unlock()
}

func (pi *ProcessInternal) GetProcess() *fgs.Process {
	pi.mu.Lock()
	return pi.process
}

func (pi *ProcessInternal) PutProcess() {
	pi.mu.Unlock()
}

func (pi *ProcessInternal) UnsafeGetProcess() *fgs.Process {
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

func (pi *ProcessInternal) UnsafeGetProcessCap() *fgs.Capabilities {
	return pi.capabilities
}

func (pi *ProcessInternal) RefDec() {
	procCache.refDec(pi)
}

func (pi *ProcessInternal) RefInc() {
	procCache.refInc(pi)
}

func GetProcessID(pid uint32, ktime uint64) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", nodeName, ktime, pid)))
}

func GetExecID(proc *fgsAPI.MsgProcess) string {
	return GetProcessID(proc.PID, proc.Ktime)
}

func GetExecIDFromKey(key *fgsAPI.MsgExecveKey) string {
	return GetProcessID(key.Pid, key.Ktime)
}

func GetProcess(
	process fgsAPI.MsgProcess,
	containerID string,
	parent fgsAPI.MsgExecveKey,
	capabilities fgsAPI.MsgCapabilities,
	namespaces fgsAPI.MsgNamespaces,
) (*ProcessInternal, *hubblev1.Endpoint) {
	args, cwd := ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	if parent.Pid != 0 {
		parentExecID = GetExecIDFromKey(&parent)
	}
	execID := GetExecID(&process)
	protoPod, endpoint := k8s.GetPodInfo(containerID, process.Filename, args, process.NSPID)
	caps := caps.GetMsgCapabilities(capabilities)
	ns := namespace.GetMsgNamespaces(namespaces)
	return &ProcessInternal{
		process: &fgs.Process{
			Pid:          &wrapperspb.UInt32Value{Value: process.PID},
			Uid:          &wrapperspb.UInt32Value{Value: process.UID},
			Cwd:          path.MarkUnresolvedPathComponentsCwd(cwd, process.Flags),
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

func GetPodInfo(cid, bin, args string, nspid uint32) (*fgs.Pod, *hubblev1.Endpoint) {
	return k8s.GetPodInfo(cid, bin, args, nspid)
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

// Add converts an FGS exec event to protobuf format and adds the protobuf message to the cache.
func Add(event *fgsAPI.MsgExecveEventUnix) *ProcessInternal {
	proc, _ := GetProcess(event.Process, event.Kube.Docker, event.Parent, event.Capabilities, event.Namespaces)
	procCache.Add(proc)

	var parentExecID string
	if proc.process.Pid != nil {
		parentExecID = procCache.getFromPidMap(proc.process.Pid.Value)
		procCache.AddToPidMap(proc.process.Pid.Value, proc.process.ExecId)
	}
	if strings.Contains(proc.process.Flags, "clone") || strings.Contains(proc.process.Flags, "procFS") {
		return proc
	}
	// This means the exec didn't clone. Look up the most recent exec ID for this PID
	// and use that as the parent.
	parent, err := procCache.get(parentExecID)
	if err != nil {
		metrics.ErrorCount.WithLabelValues(string(metrics.NoParentNoClone)).Inc()
		logger.GetLogger().WithFields(logrus.Fields{
			"parent exec id": parentExecID,
			"process":        proc,
		}).Debug("parent not found in cache")
		return proc
	}
	if parent.process.ExecId == proc.process.ExecId {
		logger.GetLogger().WithFields(logrus.Fields{
			"parent":  parent,
			"current": proc,
		}).Warn("parent and current process has the same exec ID")
		return proc
	}
	proc.process.ParentExecId = parent.process.ExecId
	return proc
}

func Get(execId string) (*ProcessInternal, error) {
	return procCache.get(execId)
}

func GetProcessEndpoint(p *fgs.Process) *hubblev1.Endpoint {
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
