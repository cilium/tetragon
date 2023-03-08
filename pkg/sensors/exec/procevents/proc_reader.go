// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
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

type Procs struct {
	psize                uint32
	ppid                 uint32
	pnspid               uint32
	pflags               uint32
	pktime               uint64
	pargs                []byte
	size                 uint32
	uid                  uint32
	pid                  uint32
	nspid                uint32
	auid                 uint32
	flags                uint32
	ktime                uint64
	args                 []byte
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
}

func procKernel() Procs {
	kernelArgs := []byte("<kernel>\u0000")
	return Procs{
		psize:       uint32(processapi.MSG_SIZEOF_EXECVE + len(kernelArgs) + processapi.MSG_SIZEOF_CWD),
		ppid:        kernelPid,
		pnspid:      0,
		pflags:      api.EventProcFS,
		pktime:      1,
		pargs:       kernelArgs,
		size:        uint32(processapi.MSG_SIZEOF_EXECVE + len(kernelArgs) + processapi.MSG_SIZEOF_CWD),
		uid:         0,
		pid:         kernelPid,
		nspid:       0,
		auid:        0,
		flags:       api.EventProcFS,
		ktime:       1,
		args:        kernelArgs,
		effective:   0,
		inheritable: 0,
		permitted:   0,
	}
}

func getCWD(pid uint32) (string, uint32) {
	flags := uint32(0)
	pidstr := fmt.Sprint(pid)

	if pid == 0 {
		return "", flags
	}

	cwd, err := os.Readlink(filepath.Join(option.Config.ProcFS, pidstr, "cwd"))
	if err != nil {
		flags |= api.EventRootCWD | api.EventErrorCWD
		return " ", flags
	}

	if cwd == "/" {
		cwd = " "
		flags |= api.EventRootCWD
	}
	return cwd, flags
}

func pushExecveEvents(p Procs) {
	var err error

	args, filename := procsFilename(p.args)
	cwd, flags := getCWD(p.pid)
	if (flags & api.EventRootCWD) == 0 {
		args = args + " " + cwd
	}

	m := exec.MsgExecveEventUnix{}
	m.Common.Op = ops.MSG_OP_EXECVE
	m.Common.Size = processapi.MsgUnixSize + p.psize + p.size

	m.Kube.NetNS = 0
	m.Kube.Cid = 0
	m.Kube.Cgrpid = 0
	m.Kube.Docker, err = procsDockerId(p.pid)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Procfs execve event pods/ identifier error")
	}

	m.Parent.Pid = p.ppid
	m.Parent.Ktime = p.pktime

	m.Capabilities.Permitted = p.permitted
	m.Capabilities.Effective = p.effective
	m.Capabilities.Inheritable = p.inheritable

	m.Namespaces.UtsInum = p.uts_ns
	m.Namespaces.IpcInum = p.ipc_ns
	m.Namespaces.MntInum = p.mnt_ns
	m.Namespaces.PidInum = p.pid_ns
	m.Namespaces.PidChildInum = p.pid_for_children_ns
	m.Namespaces.NetInum = p.net_ns
	m.Namespaces.TimeInum = p.time_ns
	m.Namespaces.TimeChildInum = p.time_for_children_ns
	m.Namespaces.CgroupInum = p.cgroup_ns
	m.Namespaces.UserInum = p.user_ns

	m.Process.Size = p.size
	m.Process.PID = p.pid
	m.Process.NSPID = p.nspid
	m.Process.UID = p.uid
	m.Process.AUID = p.auid
	m.Process.Flags = p.flags | flags
	m.Process.Ktime = p.ktime
	m.Common.Ktime = p.ktime
	m.Process.Filename = filename
	m.Process.Args = args

	observer.AllListeners(&m)
}

func updateExecveMapStats(procs int64) {

	execveMapStats := base.GetExecveMapStats()

	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), execveMapStats.Name), nil)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("Could not open execve_map_stats")
		return
	}
	defer m.Close()

	if err := sensors.UpdateStatsMap(m, procs); err != nil {
		logger.GetLogger().WithError(err).
			Errorf("Failed to update execve_map_stats with procfs stats: %s", err)
	}
}

func writeExecveMap(procs []Procs) {
	mapDir := bpf.MapPrefixPath()

	execveMap := base.GetExecveMap()

	m, err := bpf.OpenMap(filepath.Join(mapDir, execveMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(mapDir, execveMap.Name))
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			panic(err)
		}
	}
	for _, p := range procs {
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

		m.Update(k, v)
	}
	// In order for kprobe events from kernel ctx to not abort we need the
	// execve lookup to map to a valid entry. So to simplify the kernel side
	// and avoid having to add another branch of logic there to handle pid==0
	// case we simply add it here.
	m.Update(&execvemap.ExecveKey{Pid: kernelPid}, &execvemap.ExecveValue{
		Parent: processapi.MsgExecveKey{
			Pid:   kernelPid,
			Ktime: 1},
		Process: processapi.MsgExecveKey{
			Pid:   kernelPid,
			Ktime: 1,
		},
	})
	m.Close()

	updateExecveMapStats(int64(len(procs)))
}

func pushEvents(procs []Procs) {
	writeExecveMap(procs)

	sort.Slice(procs, func(i, j int) bool {
		return procs[i].ppid < procs[j].ppid
	})
	procs = append(procs, procKernel())
	for _, p := range procs {
		pushExecveEvents(p)
	}
}

func GetRunningProcs() []Procs {
	var procs []Procs

	procFS, err := os.ReadDir(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("Could not read directory %s", option.Config.ProcFS)
		return nil
	}

	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	// time and time_for_children namespaces introduced in kernel 5.6
	hasTimeNs := (int64(kernelVer) >= kernels.KernelStringToNumeric("5.6.0"))

	for _, d := range procFS {
		var pcmdline []byte
		var pstats []string
		var pktime uint64
		var pexecPath string
		var pnspid uint32

		if d.IsDir() == false {
			continue
		}

		pathName := filepath.Join(option.Config.ProcFS, d.Name())

		cmdline, err := os.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}

		pid, err := proc.GetProcPid(d.Name())
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("pid read error")
			continue
		}

		stats, err := proc.GetProcStatStrings(pathName)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("stats read error")
			continue
		}

		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			_ppid = 0 // 0 pid indicates no known parent
		}

		ktime, err := proc.GetStatsKtime(stats)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("ktime read error")
		}

		// Initialize with invalid uid
		euid := proc.InvalidUid
		auid := proc.InvalidUid
		// Get process status
		status, err := proc.GetStatus(pathName)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Reading process status error")
		} else {
			_, euid, err = proc.GetUids(status)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading Uids of %s failed, falling back to uid: %d", pathName, uint32(euid))
			}

			auid, err = proc.GetLoginUid(status)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading Loginuid of %s failed, falling back to loginuid: %d", pathName, uint32(auid))
			}
		}

		nspid, permitted, effective, inheritable := caps.GetPIDCaps(filepath.Join(option.Config.ProcFS, d.Name(), "status"))

		uts_ns := namespace.GetPidNsInode(uint32(pid), "uts")
		ipc_ns := namespace.GetPidNsInode(uint32(pid), "ipc")
		mnt_ns := namespace.GetPidNsInode(uint32(pid), "mnt")
		pid_ns := namespace.GetPidNsInode(uint32(pid), "pid")
		pid_for_children_ns := namespace.GetPidNsInode(uint32(pid), "pid_for_children")
		net_ns := namespace.GetPidNsInode(uint32(pid), "net")
		time_ns := uint32(0)
		time_for_children_ns := uint32(0)
		if hasTimeNs {
			time_ns = namespace.GetPidNsInode(uint32(pid), "time")
			time_for_children_ns = namespace.GetPidNsInode(uint32(pid), "time_for_children")
		}
		cgroup_ns := namespace.GetPidNsInode(uint32(pid), "cgroup")
		user_ns := namespace.GetPidNsInode(uint32(pid), "user")

		// On error procsDockerId zeros dockerId so we can ignore any errors.
		dockerId, _ := procsDockerId(uint32(pid))
		if dockerId == "" {
			// If we do not have a container ID, then set nspid to zero.
			// This field is used to construct the pod information to
			// identify pids inside the container.
			nspid = 0
		}

		if _ppid != 0 {
			var err error
			parentPath := filepath.Join(option.Config.ProcFS, ppid)

			pcmdline, err = os.ReadFile(filepath.Join(parentPath, "cmdline"))
			if err != nil {
				logger.GetLogger().WithError(err).WithField("path", parentPath).Warn("parent cmdline error")
				continue
			}

			pstats, err = proc.GetProcStatStrings(string(parentPath))
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("parent stats read error")
				continue
			}

			pktime, err = proc.GetStatsKtime(pstats)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("parent ktime read error")
			}

			if dockerId != "" {
				// We have a container ID so let's get the nspid inside.
				pnspid, _, _, _ = caps.GetPIDCaps(filepath.Join(option.Config.ProcFS, ppid, "status"))
			}
		} else {
			pcmdline = nil
			pstats = nil
			pktime = 0
			pnspid = 0
		}

		execPath, err := os.Readlink(filepath.Join(option.Config.ProcFS, d.Name(), "exe"))
		if err == nil {
			cmdline = proc.PrependPath(execPath, cmdline)
		}

		if _ppid != 0 {
			pexecPath, err = os.Readlink(filepath.Join(option.Config.ProcFS, ppid, "exe"))
			if err == nil {
				pcmdline = proc.PrependPath(pexecPath, pcmdline)
			}
		} else {
			pexecPath = ""
		}

		pcmdsUTF := stringToUTF8(pcmdline)
		cmdsUTF := stringToUTF8(cmdline)

		p := Procs{
			ppid: uint32(_ppid), pnspid: pnspid, pargs: pcmdsUTF,
			pflags: api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			pktime: pktime,
			uid:    euid, // use euid to be compatible with ps
			auid:   auid,
			pid:    uint32(pid), nspid: nspid, args: cmdsUTF,
			flags:                api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			ktime:                ktime,
			permitted:            permitted,
			effective:            effective,
			inheritable:          inheritable,
			uts_ns:               uts_ns,
			ipc_ns:               ipc_ns,
			mnt_ns:               mnt_ns,
			pid_ns:               pid_ns,
			pid_for_children_ns:  pid_for_children_ns,
			net_ns:               net_ns,
			time_ns:              time_ns,
			time_for_children_ns: time_for_children_ns,
			cgroup_ns:            cgroup_ns,
			user_ns:              user_ns,
		}

		p.size = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.args) + processapi.MSG_SIZEOF_CWD)
		p.psize = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.pargs) + processapi.MSG_SIZEOF_CWD)
		/* If we can't fit this in the buffer lets trim some parts and
		 * make it fit.
		 */
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
				if len(p.pargs) > len(p.args) {
					p.pflags |= api.EventTruncArgs
					p.pargs = p.pargs[:len(p.pargs)-1]
					p.psize--
				} else {
					p.flags |= api.EventTruncArgs
					p.args = p.args[:len(p.args)-1]
					p.size--
				}
			}
		}

		procs = append(procs, p)
	}
	logger.GetLogger().Infof("Read ProcFS %s appended %d/%d entries", option.Config.ProcFS, len(procs), len(procFS))

	pushEvents(procs)
	return procs
}
