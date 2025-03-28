// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/cilium/tetragon/pkg/sensors/exec/userinfo"
	"github.com/sirupsen/logrus"
)

const (
	maxMapRetries = 4
	mapRetryDelay = 1

	kernelPid = uint32(0)
)

func stringToUTF8(s []byte) []byte {
	var utf8Cursor int
	var i int

	for i < len(s) {
		r, size := utf8.DecodeRune(s[i:])
		utf8Cursor += utf8.EncodeRune(s[utf8Cursor:], r)
		i += size
	}
	return s
}

type procs struct {
	psize                uint32
	ppid                 uint32
	pnspid               uint32
	pflags               uint32
	pktime               uint64
	pcmdline             []byte
	pexe                 []byte
	size                 uint32
	uids                 []uint32
	gids                 []uint32
	pid                  uint32
	tid                  uint32
	nspid                uint32
	auid                 uint32
	flags                uint32
	ktime                uint64
	cmdline              []byte
	exe                  []byte
	effective            uint64
	inheritable          uint64
	permitted            uint64
	uts_ns               uint32
	ipc_ns               uint32
	mnt_ns               uint32
	pid_ns               uint32
	pid_for_children_ns  uint32
	net_ns               uint32
	time_ns              uint32
	time_for_children_ns uint32
	cgroup_ns            uint32
	user_ns              uint32
	kernel_thread        bool
}

func (p procs) args() []byte {
	// exe and cmdline are already in UTF8
	return proc.PrependPath(string(p.exe), p.cmdline)
}

func (p procs) pargs() []byte {
	return proc.PrependPath(string(p.pexe), p.pcmdline)
}

func pushExecveEvents(p procs) {
	var err error

	/* If we can't fit this in the buffer lets trim some parts and
	 * make it fit.
	 */
	raw_args := p.args()
	raw_pargs := p.pargs()

	if p.size+p.psize > processapi.MSG_SIZEOF_BUFFER {
		var deduct uint32
		var need int32

		need = int32((p.size + p.psize) - processapi.MSG_SIZEOF_BUFFER)
		// First consume CWD space from parent because this speculative extra space
		// next try to consume CWD space from child and finally start truncating args
		// if necessary.
		deduct = processapi.MSG_SIZEOF_CWD
		p.pflags = p.pflags & ^uint32(api.EventNeedsCWD)
		p.pflags = p.pflags | api.EventNoCWDSupport
		p.psize -= deduct
		need -= int32(deduct)
		if need > 0 {
			deduct = processapi.MSG_SIZEOF_CWD
			p.size -= deduct
			p.flags = p.flags & ^uint32(api.EventNeedsCWD)
			p.flags = p.flags | api.EventNoCWDSupport
			need -= int32(deduct)
		}

		for i := int32(0); i < need; i++ {
			if len(raw_pargs) > len(raw_args) {
				p.pflags |= api.EventTruncArgs
				raw_pargs = raw_pargs[:len(raw_pargs)-1]
				p.psize--
			} else {
				p.flags |= api.EventTruncArgs
				raw_args = raw_args[:len(raw_args)-1]
				p.size--
			}
		}
	}

	args, filename := procsFilename(raw_args)
	cwd, flags := getCWD(p.pid)
	if (flags & api.EventRootCWD) == 0 {
		args = args + " " + cwd
	}

	// If this is a kernel thread, we use its filename as process name
	// similarly to what ps reports.
	if p.kernel_thread {
		filename = fmt.Sprintf("[%s]", filename)
		args = ""
	}

	if p.kernel_thread {
		m := exec.MsgKThreadInitUnix{}
		m.Unix = &processapi.MsgExecveEventUnix{}
		m.Unix.Msg = &processapi.MsgExecveEvent{}

		m.Unix.Msg.Common = processapi.MsgCommon{}
		m.Unix.Msg.Kube = processapi.MsgK8s{}
		m.Unix.Msg.CleanupProcess = processapi.MsgExecveKey{}

		m.Unix.Msg.Parent.Pid = p.ppid
		m.Unix.Msg.Parent.Ktime = p.pktime

		m.Unix.Msg.Creds.Cap = processapi.MsgCapabilities{}
		m.Unix.Msg.Namespaces = processapi.MsgNamespaces{}

		m.Unix.Process.Size = p.size
		m.Unix.Process.PID = p.pid
		m.Unix.Process.TID = p.pid
		m.Unix.Process.NSPID = p.nspid
		m.Unix.Process.UID = 0
		m.Unix.Process.AUID = proc.InvalidUid

		m.Unix.Process.Flags = api.EventProcFS
		m.Unix.Process.Ktime = p.ktime
		m.Unix.Process.Filename = filename
		m.Unix.Process.Args = ""

		observer.AllListeners(&m)
	} else {
		m := exec.MsgExecveEventUnix{}
		m.Unix = &processapi.MsgExecveEventUnix{}
		m.Unix.Msg = &processapi.MsgExecveEvent{}
		m.Unix.Msg.Common.Op = ops.MSG_OP_EXECVE
		m.Unix.Msg.Common.Size = processapi.MsgUnixSize + p.psize + p.size

		m.Unix.Msg.Kube.Cgrpid = 0
		if p.pid > 0 {
			m.Unix.Kube.Docker, err = procsDockerId(p.pid)
			if err != nil {
				logger.GetLogger().WithError(err).Warn("Procfs execve event pods/ identifier error")
			}
			if m.Unix.Kube.Docker != "" {
				if cgid, err := cgroups.CgroupIDFromPID(p.pid); err == nil {
					m.Unix.Msg.Kube.Cgrpid = cgid
					m.Unix.Kube.Cgrpid = cgid
				} else if option.Config.EnableCgIDmap {
					// only warn if cgidmap is enabled since this is where this
					// value is used
					logger.GetLogger().WithError(err).WithField("pid", p.pid).Warn("failed to find cgroup id for pid")
				}
			}
		}

		m.Unix.Msg.Parent.Pid = p.ppid
		m.Unix.Msg.Parent.Ktime = p.pktime

		caps := processapi.MsgCapabilities{
			Permitted:   p.permitted,
			Effective:   p.effective,
			Inheritable: p.inheritable,
		}

		m.Unix.Msg.Namespaces.UtsInum = p.uts_ns
		m.Unix.Msg.Namespaces.IpcInum = p.ipc_ns
		m.Unix.Msg.Namespaces.MntInum = p.mnt_ns
		m.Unix.Msg.Namespaces.PidInum = p.pid_ns
		m.Unix.Msg.Namespaces.PidChildInum = p.pid_for_children_ns
		m.Unix.Msg.Namespaces.NetInum = p.net_ns
		m.Unix.Msg.Namespaces.TimeInum = p.time_ns
		m.Unix.Msg.Namespaces.TimeChildInum = p.time_for_children_ns
		m.Unix.Msg.Namespaces.CgroupInum = p.cgroup_ns
		m.Unix.Msg.Namespaces.UserInum = p.user_ns

		m.Unix.Process.Size = p.size
		m.Unix.Process.PID = p.pid
		m.Unix.Process.TID = p.tid
		m.Unix.Process.NSPID = p.nspid
		// use euid to be compatible with ps
		m.Unix.Process.UID = p.uids[1]
		m.Unix.Process.AUID = p.auid
		m.Unix.Msg.Creds = processapi.MsgGenericCred{
			Uid: p.uids[0], Euid: p.uids[1], Suid: p.uids[2], FSuid: p.uids[3],
			Gid: p.gids[0], Egid: p.gids[1], Sgid: p.gids[2], FSgid: p.gids[3],
			Cap: caps,
		}
		m.Unix.Process.Flags = p.flags | flags
		m.Unix.Process.Ktime = p.ktime
		m.Unix.Msg.Common.Ktime = p.ktime
		m.Unix.Process.Filename = filename
		m.Unix.Process.Args = args

		err := userinfo.MsgToExecveAccountUnix(m.Unix)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"process.pid":    p.pid,
				"process.binary": filename,
				"process.uid":    m.Unix.Process.UID,
			}).WithError(err).Trace("Resolving process uid to username record failed")
		}

		observer.AllListeners(&m)
	}
}

func procToKeyValue(p procs, inInitTree map[uint32]struct{}) (*execvemap.ExecveKey, *execvemap.ExecveValue) {
	k := &execvemap.ExecveKey{Pid: p.pid}
	v := &execvemap.ExecveValue{}

	v.Parent.Pid = p.ppid
	v.Parent.Ktime = p.pktime
	v.Process.Pid = p.pid
	v.Process.Ktime = p.ktime
	v.Flags = 0
	v.Nspid = p.nspid
	v.Capabilities.Permitted = p.permitted
	v.Capabilities.Effective = p.effective
	v.Capabilities.Inheritable = p.inheritable
	v.Namespaces.UtsInum = p.uts_ns
	v.Namespaces.IpcInum = p.ipc_ns
	v.Namespaces.MntInum = p.mnt_ns
	v.Namespaces.PidInum = p.pid_ns
	v.Namespaces.PidChildInum = p.pid_for_children_ns
	v.Namespaces.NetInum = p.net_ns
	v.Namespaces.TimeInum = p.time_ns
	v.Namespaces.TimeChildInum = p.time_for_children_ns
	v.Namespaces.CgroupInum = p.cgroup_ns
	v.Namespaces.UserInum = p.user_ns
	pathLength := copy(v.Binary.Path[:], p.exe)
	v.Binary.PathLength = int32(pathLength)

	_, parentInInitTree := inInitTree[p.ppid]
	if v.Nspid == 1 || parentInInitTree {
		v.Flags |= api.EventInInitTree
		inInitTree[p.pid] = struct{}{}
	}

	return k, v
}

func pushEvents(ps []procs) {
	writeExecveMap(ps)

	sort.Slice(ps, func(i, j int) bool {
		return ps[i].ppid < ps[j].ppid
	})
	ps = append([]procs{procKernel()}, ps...)
	for _, p := range ps {
		pushExecveEvents(p)
	}
}

func GetRunningProcs() error {
	procs, err := listRunningProcs(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("Failed to list running processes from '%s'", option.Config.ProcFS)
		return err
	}

	pushEvents(procs)
	return nil
}
