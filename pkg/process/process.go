// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/path"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/watcher"
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
	refcnt atomic.Uint32
	// refcntOps is a map of operations to refcnt change
	// keys can be:
	// - "process++": process increased refcnt (i.e. this process starts)
	// - "process--": process decreased refcnt (i.e. this process exits)
	// - "parent++": parent increased refcnt (i.e. a process starts that has this process as a parent)
	// - "parent--": parent decreased refcnt (i.e. a process exits that has this process as a parent)
	refcntOps map[string]int32
	// protects the refcntOps map
	refcntOpsLock sync.Mutex
}

var (
	procCache *Cache
	k8s       watcher.PodAccessor
)

var (
	ErrProcessInfoMissing = errors.New("failed process info missing")
)

func InitCache(w watcher.PodAccessor, size int, GCInterval time.Duration) error {
	var err error

	if procCache != nil {
		FreeCache()
	}

	k8s = w
	procCache, err = NewCache(size, GCInterval)
	if err != nil {
		k8s = nil
	}
	return err
}

func FreeCache() {
	procCache.purge()
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
	proc.Refcnt = pi.refcnt.Load()
	return proc
}

// cloneInternalProcessCopy() duplicates ProcessInternal, sets its refcnt to 1
// and returns it
func (pi *ProcessInternal) cloneInternalProcessCopy() *ProcessInternal {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	npi := &ProcessInternal{
		process:       proto.Clone(pi.process).(*tetragon.Process),
		capabilities:  pi.capabilities,
		apiCreds:      pi.apiCreds,
		apiBinaryProp: pi.apiBinaryProp,
		namespaces:    pi.namespaces,
		refcntOps:     map[string]int32{"process++": 1},
	}
	npi.refcnt.Store(1) // Explicitly initialize refcnt to 1
	return npi
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
		return errors.New("process is nil")
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

func (pi *ProcessInternal) RefDec(reason string) {
	procCache.refDec(pi, reason+"--")
}

func (pi *ProcessInternal) RefInc(reason string) {
	procCache.refInc(pi, reason+"++")
}

func (pi *ProcessInternal) RefGet() uint32 {
	return pi.refcnt.Load()
}

func (pi *ProcessInternal) NeededAncestors() bool {
	if pi != nil && pi.process.Pid.Value > 2 {
		return true
	}
	return false
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

func GetExecID(proc *tetragonAPI.MsgProcess) string {
	return GetProcessID(proc.PID, proc.Ktime)
}

func GetExecIDFromKey(key *tetragonAPI.MsgExecveKey) string {
	return GetProcessID(key.Pid, key.Ktime)
}

func getEnvironmentVariables(envs []string) []*tetragon.EnvVar {
	res := []*tetragon.EnvVar{}

	for _, v := range envs {
		var key, val string

		idx := strings.Index(v, "=")
		if idx == -1 {
			// unlikely, but let's not just ignore
			key = "invalid"
			val = v
		} else {
			key = v[0:idx]
			val = v[idx+1:]
		}
		res = append(res, &tetragon.EnvVar{Key: key, Value: val})
	}
	return res
}

// initProcessInternalExec() initialize and returns ProcessInternal and
// hubblev1.Endpoint objects from an execve event
func initProcessInternalExec(
	event *tetragonAPI.MsgExecveEventUnix,
	parent tetragonAPI.MsgExecveKey,
) *ProcessInternal {
	process := event.Process
	args, cwd := ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	if parent.Pid != 0 {
		parentExecID = GetExecIDFromKey(&parent)
	} else {
		parentExecID = GetProcessID(0, 1)
	}
	creds := &event.Msg.Creds
	execID := GetExecID(&process)
	protoPod := GetPodInfo(event.Kube.Docker, process.Filename, args, process.NSPID)
	apiCaps := caps.GetMsgCapabilities(event.Msg.Creds.Cap)
	binary := path.GetBinaryAbsolutePath(process.Filename, cwd)
	apiNs, err := namespace.GetMsgNamespaces(event.Msg.Namespaces)
	if err != nil {
		logger.GetLogger().Warn("ExecveEvent: parsing namespaces failed",
			"event.name", "Execve",
			"event.process.pid", process.PID,
			"event.process.tid", process.TID,
			"event.process.binary", binary,
			"event.process.exec_id", execID,
			"event.parent.exec_id", parentExecID)
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
		logger.GetLogger().Warn("ExecveEvent: process PID and TID mismatch",
			"event.name", "Execve",
			"event.process.pid", process.PID,
			"event.process.tid", process.TID,
			"event.process.binary", binary,
			"event.process.exec_id", execID,
			"event.parent.exec_id", parentExecID)
		// Explicitly reset TID to be PID
		process.TID = process.PID
		errormetrics.ErrorTotalInc(errormetrics.ProcessPidTidMismatch)
	}

	envs := process.Envs

	// Apply user filter on environment variables before redaction.
	if option.Config.FilterEnvironmentVariables != nil {
		envs = slices.DeleteFunc(envs, func(v string) bool {
			idx := strings.Index(v, "=")
			_, ok := option.Config.FilterEnvironmentVariables[v[0:idx]]
			return !ok
		})
	}

	if fieldfilters.RedactionFilters != nil {
		args, envs = fieldfilters.RedactionFilters.Redact(binary, args, envs)
	}

	var user *tetragon.UserRecord

	if len(process.User.Name) != 0 {
		user = &tetragon.UserRecord{
			Name: process.User.Name,
		}
	}

	pi := &ProcessInternal{
		process: &tetragon.Process{
			Pid:                  &wrapperspb.UInt32Value{Value: process.PID},
			Tid:                  &wrapperspb.UInt32Value{Value: process.TID},
			Uid:                  &wrapperspb.UInt32Value{Value: process.UID},
			Cwd:                  cwd,
			Binary:               binary,
			Arguments:            args,
			Flags:                strings.Join(exec.DecodeCommonFlags(process.Flags), " "),
			StartTime:            ktime.ToProtoOpt(process.Ktime, (process.Flags&api.EventProcFS) == 0),
			Auid:                 &wrapperspb.UInt32Value{Value: process.AUID},
			Pod:                  protoPod,
			ExecId:               execID,
			Docker:               event.Kube.Docker,
			ParentExecId:         parentExecID,
			Refcnt:               0,
			User:                 user,
			EnvironmentVariables: getEnvironmentVariables(envs),
		},
		capabilities:  apiCaps,
		apiCreds:      apiCreds,
		apiBinaryProp: apiBinaryProp,
		namespaces:    apiNs,
		refcntOps:     map[string]int32{"process++": 1},
	}
	pi.refcnt.Store(1)

	// Set in_init_tree flag
	if event.Process.Flags&api.EventInInitTree == api.EventInInitTree {
		pi.process.InInitTree = &wrapperspb.BoolValue{Value: true}
	} else {
		pi.process.InInitTree = &wrapperspb.BoolValue{Value: false}
	}

	return pi
}

// initProcessInternalClone() initialize and returns ProcessInternal from
// a clone event
func initProcessInternalClone(event *tetragonAPI.MsgCloneEvent,
	parent *ProcessInternal, parentExecId string) (*ProcessInternal, error) {
	pi := parent.cloneInternalProcessCopy()
	if pi.process == nil {
		err := errors.New("failed to clone parent process from cache")
		logger.GetLogger().Debug("CloneEvent: parent process information is missing",
			logfields.Error, err,
			"event.name", "Clone",
			"event.parent.pid", event.Parent.Pid,
			"event.parent.exec_id", parentExecId)
		return nil, err
	}

	pi.process.ParentExecId = parentExecId
	pi.process.ExecId = GetProcessID(event.PID, event.Ktime)
	pi.process.Pid = &wrapperspb.UInt32Value{Value: event.PID}
	// Per thread tracking rules PID == TID: ensure that we get TID equals PID.
	//  Since from BPF side we only generate one clone event per
	//  thread group that is for the leader, assert on that.
	if event.PID != event.TID {
		logger.GetLogger().Debug("CloneEvent: process PID and TID mismatch",
			"event.name", "Clone",
			"event.process.pid", event.PID,
			"event.process.tid", event.TID,
			"event.process.exec_id", pi.process.ExecId,
			"event.parent.exec_id", parentExecId)
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
	// Set in_init_tree flag
	if event.Flags&api.EventInInitTree == api.EventInInitTree {
		pi.process.InInitTree = &wrapperspb.BoolValue{Value: true}
	} else {
		pi.process.InInitTree = &wrapperspb.BoolValue{Value: false}
	}

	return pi, nil
}

// GetPodInfo constructs and returns the Kubernetes Pod information associated with an an event.
func GetPodInfo(containerID, bin, args string, nspid uint32) *tetragon.Pod {
	return getPodInfo(k8s, containerID, bin, args, nspid)
}

func GetParentProcessInternal(pid uint32, ktime uint64) (*ProcessInternal, *ProcessInternal) {
	var parent, process *ProcessInternal
	var err error

	processID := GetProcessID(pid, ktime)

	if process, err = procCache.get(processID); err != nil {
		logger.GetLogger().Debug("process not found in cache",
			"id in event", processID,
			"pid", pid,
			"ktime", ktime)
		return nil, nil
	}

	if parent, err = procCache.get(process.process.ParentExecId); err != nil {
		logger.GetLogger().Debug("parent process not found in cache",
			"id in event", processID,
			"pid", pid,
			"ktime", ktime)
		return process, nil
	}
	return process, parent
}

// GetAncestorProcessesInternal returns a slice, representing a continuous sequence of ancestors
// of the process up to init process (PID 1) or kthreadd (PID 2), including the immediate parent.
func GetAncestorProcessesInternal(execId string) ([]*ProcessInternal, error) {
	var ancestors []*ProcessInternal
	var process *ProcessInternal
	var err error

	if process, err = procCache.get(execId); err != nil {
		return nil, err
	}

	// No need to include <kernel> process (PID 0)
	for process.process.Pid.Value > constants.OLDEST_ANCESTOR_PID {
		if process, err = procCache.get(process.process.ParentExecId); err != nil {
			logger.GetLogger().Debug("ancestor process not found in cache",
				logfields.Error, err,
				"id in event", execId)
			break
		}
		ancestors = append(ancestors, process)
	}

	return ancestors, err
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
	return proc
}

// AddCloneEvent adds a new process into the cache from a CloneEvent
func AddCloneEvent(event *tetragonAPI.MsgCloneEvent) (*ProcessInternal, error) {
	parentExecId := GetProcessID(event.Parent.Pid, event.Parent.Ktime)
	parent, err := Get(parentExecId)
	if err != nil {
		logger.GetLogger().Debug("CloneEvent: parent process not found in cache",
			logfields.Error, err,
			"event.name", "Clone",
			"event.parent.pid", event.Parent.Pid,
			"event.parent.exec_id", parentExecId)
		return nil, err
	}

	proc, err := initProcessInternalClone(event, parent, parentExecId)
	if err != nil {
		return nil, err
	}

	parent.RefInc("parent")
	procCache.add(proc)
	return proc, nil
}

func Get(execId string) (*ProcessInternal, error) {
	return procCache.get(execId)
}

// GetK8s returns PodAccessor. You must call InitCache before calling this function to ensure
// that k8s has been initialized.
func GetK8s() watcher.PodAccessor {
	return k8s
}

func DumpProcessCache(opts *tetragon.DumpProcessCacheReqArgs) []*tetragon.ProcessInternal {
	return procCache.dump(opts)
}

// This function returns the process cache entries (and not the copies
// of them as opposed to dump function). Thus any changes to the return
// value results in affecting the process cache entries.
// This is mainly for tests where we want to check the values of the
// process cache.
func GetCacheEntries() []*tetragon.ProcessInternal {
	return procCache.getEntries()
}
