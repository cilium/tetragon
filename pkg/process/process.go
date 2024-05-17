// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
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
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/watcher"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	apiCreds     *tetragon.ProcessCredentials
	namespaces   *tetragon.Namespaces
	// The BinaryProperties is not stored into the process, this field
	// will be constructed on the fly when returning these extra fields
	// about the binary during the corresponding ProcessExec only.
	apiBinaryProp *tetragon.BinaryProperties
	// garbage collector metadata
	color  int // Writes should happen only inside gc select channel
	refcnt uint32
}

var (
	nodeName    string
	procCache   *Cache
	ciliumState *hubble.State
	k8s         watcher.K8sResourceWatcher
)

var (
	ErrProcessInfoMissing = errors.New("failed process info missing")
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
	ProcessCacheTotal.Set(0)
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
		process:       proto.Clone(pi.process).(*tetragon.Process),
		capabilities:  pi.capabilities,
		apiCreds:      pi.apiCreds,
		apiBinaryProp: pi.apiBinaryProp,
		namespaces:    pi.namespaces,
		refcnt:        1, // Explicitly initialize refcnt to 1
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

// UpdateExecOutsideCache() checks if we must augment the ProcessExec.Process
// with more fields without propagating again those fields into the process
// cache. This means that those added fields will only show up for the
// returned ProcessExec.Process.
//
// This is usually the case where we have the core information of the process
// that was handled directly or through some event cache retries, in all cases
// the ProcessInternal.process is properly set and referenced and can't
// disappear, so we don't take any locks here.
// It operates on the direct reference and if some fields have to be added then
// a deep copy will be performed.
//
// Returns:
//  1. The updated Process in case of new or updated fields, otherwise
//     the old same Process reference.
//  2. A boolean to indicate if a process information update was performed
//
// Current rules to make a copy and add fields for Process part of ProcessExec event are:
//
//  1. process_exec.process.binary_properties:
//     a. if it is a setuid execution
//     b. if it is a setgid execution
//     c. if it is a filesystem capability execution
//     d. Execution of an unlinked binary (shm, memfd, or deleted binaries)
//
//     a b and c are subject to the --enable-process-creds flag
func (pi *ProcessInternal) UpdateExecOutsideCache(cred bool) (*tetragon.Process, bool) {
	update := false
	// Get reference on the process
	process := pi.UnsafeGetProcess()

	prop := &tetragon.BinaryProperties{}

	// Check if we should augment the process
	if cred && pi.apiBinaryProp != nil {
		// Annotate privileged execution if it was successfully set
		if pi.apiBinaryProp.Setuid.GetValue() != proc.InvalidUid {
			prop.Setuid = pi.apiBinaryProp.Setuid
			update = true
		}
		if pi.apiBinaryProp.Setgid.GetValue() != proc.InvalidUid {
			prop.Setgid = pi.apiBinaryProp.Setgid
			update = true
		}
		if pi.apiBinaryProp.PrivilegesChanged != nil {
			prop.PrivilegesChanged = pi.apiBinaryProp.PrivilegesChanged
			update = true
		}
		// Annotate execution of unlinked binaries
		if pi.apiBinaryProp.File != nil && pi.apiBinaryProp.File.Inode != nil {
			prop.File = pi.apiBinaryProp.File
			update = true
		}
	}

	// Take a copy of the process, add the necessary fields to the
	// final ProcessExec event
	if update {
		process = pi.GetProcessCopy()
		process.BinaryProperties = prop
	}

	return process, update
}

func (pi *ProcessInternal) AnnotateProcess(cred, ns bool) error {
	process := pi.getProcess()
	defer pi.putProcess()
	if process == nil {
		return fmt.Errorf("Process is nil")
	}
	if cred {
		process.Cap = pi.capabilities
		process.ProcessCredentials = pi.apiCreds
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
	event *tetragonAPI.MsgExecveEventUnix,
	parent tetragonAPI.MsgExecveKey,
) *ProcessInternal {
	process := event.Process
	containerID := event.Kube.Docker
	args, cwd := ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	if parent.Pid != 0 {
		parentExecID = GetExecIDFromKey(&parent)
	} else {
		parentExecID = GetProcessID(0, 1)
	}
	creds := &event.Msg.Creds
	execID := GetExecID(&process)
	protoPod := GetPodInfo(containerID, process.Filename, args, process.NSPID)
	apiCaps := caps.GetMsgCapabilities(event.Msg.Creds.Cap)
	binary := path.GetBinaryAbsolutePath(process.Filename, cwd)
	apiNs, err := namespace.GetMsgNamespaces(event.Msg.Namespaces)
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Execve",
			"event.process.pid":     process.PID,
			"event.process.tid":     process.TID,
			"event.process.binary":  binary,
			"event.process.exec_id": execID,
			"event.parent.exec_id":  parentExecID,
		}).Warn("ExecveEvent: parsing namespaces failed")
	}

	apiCreds := &tetragon.ProcessCredentials{
		Uid:        &wrapperspb.UInt32Value{Value: creds.Uid},
		Gid:        &wrapperspb.UInt32Value{Value: creds.Gid},
		Euid:       &wrapperspb.UInt32Value{Value: creds.Euid},
		Egid:       &wrapperspb.UInt32Value{Value: creds.Egid},
		Suid:       &wrapperspb.UInt32Value{Value: creds.Suid},
		Sgid:       &wrapperspb.UInt32Value{Value: creds.Sgid},
		Fsuid:      &wrapperspb.UInt32Value{Value: creds.FSuid},
		Fsgid:      &wrapperspb.UInt32Value{Value: creds.FSgid},
		Securebits: caps.GetSecureBitsTypes(creds.SecureBits),
	}

	apiBinaryProp := &tetragon.BinaryProperties{
		// Initialize with InvalidUid
		Setuid: &wrapperspb.UInt32Value{Value: proc.InvalidUid},
		Setgid: &wrapperspb.UInt32Value{Value: proc.InvalidUid},
		File:   nil,
	}

	if (process.SecureExec & tetragonAPI.ExecveSetuid) != 0 {
		apiBinaryProp.Setuid = &wrapperspb.UInt32Value{Value: creds.Euid}
	}
	if (process.SecureExec & tetragonAPI.ExecveSetgid) != 0 {
		apiBinaryProp.Setgid = &wrapperspb.UInt32Value{Value: creds.Egid}
	}

	apiBinaryProp.PrivilegesChanged = caps.GetPrivilegesChangedReasons(process.SecureExec)
	if process.Ino != 0 && process.Nlink == 0 {
		inode := &tetragon.InodeProperties{
			Number: process.Ino,
			Links:  &wrapperspb.UInt32Value{Value: process.Nlink},
		}
		apiBinaryProp.File = &tetragon.FileProperties{
			Inode: inode,
		}
	}

	// Per thread tracking rules PID == TID
	//
	// Ensure that exported events have the TID set. For events generated by
	// kernel threads PID will be 0, so instead of checking against 0,
	// assert that TGID == TID
	if process.PID != process.TID {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Execve",
			"event.process.pid":     process.PID,
			"event.process.tid":     process.TID,
			"event.process.binary":  binary,
			"event.process.exec_id": execID,
			"event.parent.exec_id":  parentExecID,
		}).Warn("ExecveEvent: process PID and TID mismatch")
		// Explicitly reset TID to be PID
		process.TID = process.PID
		errormetrics.ErrorTotalInc(errormetrics.ProcessPidTidMismatch)
	}

	if fieldfilters.RedactionFilters != nil {
		args = fieldfilters.RedactionFilters.Redact(binary, args)
	}

	var user *tetragon.UserRecord

	if len(process.User.Name) != 0 {
		user = &tetragon.UserRecord{
			Name: process.User.Name,
		}
	}

	return &ProcessInternal{
		process: &tetragon.Process{
			Pid:          &wrapperspb.UInt32Value{Value: process.PID},
			Tid:          &wrapperspb.UInt32Value{Value: process.TID},
			Uid:          &wrapperspb.UInt32Value{Value: process.UID},
			Cwd:          cwd,
			Binary:       binary,
			Arguments:    args,
			Flags:        strings.Join(exec.DecodeCommonFlags(process.Flags), " "),
			StartTime:    ktime.ToProtoOpt(process.Ktime, (process.Flags&api.EventProcFS) == 0),
			Auid:         &wrapperspb.UInt32Value{Value: process.AUID},
			Pod:          protoPod,
			ExecId:       execID,
			Docker:       containerID,
			ParentExecId: parentExecID,
			Refcnt:       0,
			User:         user,
		},
		capabilities:  apiCaps,
		apiCreds:      apiCreds,
		apiBinaryProp: apiBinaryProp,
		namespaces:    apiNs,
		refcnt:        1,
	}
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
	// Per thread tracking rules PID == TID: ensure that we get TID equals PID.
	//  Since from BPF side we only generate one clone event per
	//  thread group that is for the leader, assert on that.
	if event.PID != event.TID {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Clone",
			"event.process.pid":     event.PID,
			"event.process.tid":     event.TID,
			"event.process.exec_id": pi.process.ExecId,
			"event.parent.exec_id":  parentExecId,
		}).Debug("CloneEvent: process PID and TID mismatch")
		errormetrics.ErrorTotalInc(errormetrics.ProcessPidTidMismatch)
	}
	// Set the TID here and if we have an exit without an exec we report
	// directly this TID without copying again objects.
	// At kprobe times we use the returned TIDs from bpf side.
	pi.process.Tid = &wrapperspb.UInt32Value{Value: event.PID}

	pi.process.Flags = strings.Join(exec.DecodeCommonFlags(event.Flags), " ")
	pi.process.StartTime = ktime.ToProto(event.Ktime)
	pi.process.Refcnt = 1
	if pi.process.Pod != nil && pi.process.Pod.Container != nil {
		// Set the pid inside the container
		pi.process.Pod.Container.Pid = &wrapperspb.UInt32Value{Value: event.NSPID}
	}
	if option.Config.EnableK8s && pi.process.Docker != "" && pi.process.Pod == nil {
		if podInfo := GetPodInfo(pi.process.Docker, pi.process.Binary, pi.process.Arguments, event.NSPID); podInfo != nil {
			pi.AddPodInfo(podInfo)
		}
	}

	return pi, nil
}

// GetPodInfo constructs and returns the Kubernetes Pod information associated with
// the Container ID and the PID inside this container.
func GetPodInfo(cid, bin, args string, nspid uint32) *tetragon.Pod {
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
	if event.Msg.CleanupProcess.Ktime == 0 || event.Process.Flags&api.EventClone != 0 {
		// there is a case where we cannot find this entry in execve_map
		// in that case we use as parent what Linux knows
		proc = initProcessInternalExec(event, event.Msg.Parent)
	} else {
		proc = initProcessInternalExec(event, event.Msg.CleanupProcess)
	}

	procCache.add(proc)
	ProcessCacheTotal.Inc()
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
	ProcessCacheTotal.Inc()
	return nil
}

func Get(execId string) (*ProcessInternal, error) {
	return procCache.get(execId)
}

// GetK8s returns K8sResourceWatcher. You must call InitCache before calling this function to ensure
// that k8s has been initialized.
func GetK8s() watcher.K8sResourceWatcher {
	return k8s
}
