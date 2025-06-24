// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
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
)

func procKernel() procs {
	kernelArgs := []byte("<kernel>\u0000")
	return procs{
		psize:       uint32(processapi.MSG_SIZEOF_EXECVE + len(kernelArgs) + processapi.MSG_SIZEOF_CWD),
		ppid:        kernelPid,
		pnspid:      0,
		pflags:      api.EventProcFS,
		pktime:      1,
		pexe:        kernelArgs,
		size:        uint32(processapi.MSG_SIZEOF_EXECVE + len(kernelArgs) + processapi.MSG_SIZEOF_CWD),
		pid:         kernelPid,
		tid:         kernelPid,
		nspid:       0,
		auid:        proc.InvalidUID,
		flags:       api.EventProcFS,
		ktime:       1,
		exe:         kernelArgs,
		uids:        []uint32{0, 0, 0, 0},
		gids:        []uint32{0, 0, 0, 0},
		effective:   0,
		inheritable: 0,
		permitted:   0,
	}
}

func getCWD(pid uint32) (string, uint32) {
	flags := uint32(0)
	pidstr := strconv.FormatUint(uint64(pid), 10)

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

func updateExecveMapStats(procs int64) {

	execveMapStats := base.GetExecveMapStats()

	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), execveMapStats.Name), nil)
	if err != nil {
		logger.GetLogger().Error("Could not open execve_map_stats", logfields.Error, err)
		return
	}
	defer m.Close()

	if err := sensors.UpdateStatsMap(m, procs); err != nil {
		logger.GetLogger().Error("Failed to update execve_map_stats with procfs stats", logfields.Error, err)
	}
}

func writeExecveMap(procs []procs) {
	mapDir := bpf.MapPrefixPath()

	execveMap := base.GetExecveMap()

	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, execveMap.Name), nil)
	for i := 0; err != nil; i++ {
		m, err = ebpf.LoadPinnedMap(filepath.Join(mapDir, execveMap.Name), nil)
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
		pathLength := copy(v.Binary.Path[:], p.exe)
		v.Binary.PathLength = int32(pathLength)

		err := m.Put(k, v)
		if err != nil {
			logger.GetLogger().Warn("failed to put value in execve_map", "value", v, logfields.Error, err)
		}
	}
	// In order for kprobe events from kernel ctx to not abort we need the
	// execve lookup to map to a valid entry. So to simplify the kernel side
	// and avoid having to add another branch of logic there to handle pid==0
	// case we simply add it here.
	m.Put(&execvemap.ExecveKey{Pid: kernelPid}, &execvemap.ExecveValue{
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

func listRunningProcs(procPath string) ([]procs, error) {
	var processes []procs

	procFS, err := os.ReadDir(procPath)
	if err != nil {
		return nil, err
	}

	cgroupNsWarned := false
	pidForChildrenWarned := false

	for _, d := range procFS {
		var pcmdline []byte
		var pstats []string
		var pktime uint64
		var pexecPath string
		var pnspid uint32

		if !d.IsDir() {
			continue
		}

		// All processes have a directory name that consists from a number.
		if !regexp.MustCompile(`\d`).MatchString(d.Name()) {
			continue
		}

		pathName := filepath.Join(procPath, d.Name())

		cmdline, err := os.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}

		// We read comm in the case where cmdling is empty (i.e. kernel thread).
		comm, err := os.ReadFile(filepath.Join(pathName, "comm"))
		if err != nil {
			continue
		}

		kernelThread := false
		if string(cmdline) == "" {
			cmdline = comm
			kernelThread = true
		}

		pid, err := proc.GetProcPid(d.Name())
		if err != nil {
			logger.GetLogger().Warn("pid read error", logfields.Error, err)
			continue
		}

		stats, err := proc.GetProcStatStrings(pathName)
		if err != nil {
			logger.GetLogger().Warn("stats read error", logfields.Error, err)
			continue
		}

		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			_ppid = 0 // 0 pid indicates no known parent
		}

		ktime, err := proc.GetStatsKtime(stats)
		if err != nil {
			logger.GetLogger().Warn("ktime read error", logfields.Error, err)
		}

		// Initialize with invalid uid
		uids := []uint32{proc.InvalidUID, proc.InvalidUID, proc.InvalidUID, proc.InvalidUID}
		gids := []uint32{proc.InvalidUID, proc.InvalidUID, proc.InvalidUID, proc.InvalidUID}
		auid := proc.InvalidUID
		// Get process status
		status, err := proc.GetStatus(pathName)
		if err != nil {
			logger.GetLogger().Warn("Reading process status error", logfields.Error, err)
		} else {
			uids, err = status.GetUids()
			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Reading Uids of %s failed, falling back to uid: %d", pathName, proc.InvalidUID), logfields.Error, err)
			}

			gids, err = status.GetGIDs()
			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Reading Uids of %s failed, falling back to gid: %d", pathName, proc.InvalidUID), logfields.Error, err)
			}

			auid, err = status.GetLoginUID()
			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Reading Loginuid of %s failed, falling back to loginuid: %d", pathName, uint32(auid)), logfields.Error, err)
			}
		}

		nspid, permitted, effective, inheritable := caps.GetPIDCaps(filepath.Join(procPath, d.Name(), "status"))

		uts_ns, err := namespace.GetPidNsInode(uint32(pid), "uts")
		if err != nil {
			logger.GetLogger().Warn("Reading uts namespace failed", logfields.Error, err)
		}
		ipc_ns, err := namespace.GetPidNsInode(uint32(pid), "ipc")
		if err != nil {
			logger.GetLogger().Warn("Reading ipc namespace failed", logfields.Error, err)
		}
		mnt_ns, err := namespace.GetPidNsInode(uint32(pid), "mnt")
		if err != nil {
			logger.GetLogger().Warn("Reading mnt namespace failed", logfields.Error, err)
		}
		pid_ns, err := namespace.GetPidNsInode(uint32(pid), "pid")
		if err != nil {
			logger.GetLogger().Warn("Reading pid namespace failed", logfields.Error, err)
		}
		pid_for_children_ns, err := namespace.GetPidNsInode(uint32(pid), "pid_for_children")
		if err != nil && !pidForChildrenWarned {
			logger.GetLogger().Warn("Reading pid_for_children namespace failed", logfields.Error, err)
			pidForChildrenWarned = true
		}
		net_ns, err := namespace.GetPidNsInode(uint32(pid), "net")
		if err != nil {
			logger.GetLogger().Warn("Reading net namespace failed", logfields.Error, err)
		}
		time_ns := uint32(0)
		time_for_children_ns := uint32(0)
		if namespace.TimeNsSupport {
			time_ns, err = namespace.GetPidNsInode(uint32(pid), "time")
			if err != nil {
				logger.GetLogger().Warn("Reading time namespace failed", logfields.Error, err)
			}
			time_for_children_ns, err = namespace.GetPidNsInode(uint32(pid), "time_for_children")
			if err != nil {
				logger.GetLogger().Warn("Reading time_for_children namespace failed", logfields.Error, err)
			}
		}
		cgroup_ns, err := namespace.GetPidNsInode(uint32(pid), "cgroup")
		if err != nil && !cgroupNsWarned {
			logger.GetLogger().Warn("Reading cgroup namespace failed", logfields.Error, err)
			cgroupNsWarned = true
		}
		user_ns, err := namespace.GetPidNsInode(uint32(pid), "user")
		if err != nil {
			logger.GetLogger().Warn("Reading user namespace failed", logfields.Error, err)
		}

		// On error procsDockerId zeros dockerID so we can ignore any errors.
		dockerID, _ := procsDockerID(uint32(pid))
		if dockerID == "" {
			// If we do not have a container ID, then set nspid to zero.
			// This field is used to construct the pod information to
			// identify pids inside the container.
			nspid = 0
		}

		if _ppid != 0 {
			var err error
			parentPath := filepath.Join(procPath, ppid)

			pcmdline, err = os.ReadFile(filepath.Join(parentPath, "cmdline"))
			if err != nil {
				logger.GetLogger().Warn("parent cmdline error", "path", parentPath, logfields.Error, err)
				continue
			}

			pcomm, err := os.ReadFile(filepath.Join(parentPath, "comm"))
			if err != nil {
				continue
			}

			if string(pcmdline) == "" {
				pcmdline = pcomm
			}

			pstats, err = proc.GetProcStatStrings(string(parentPath))
			if err != nil {
				logger.GetLogger().Warn("parent stats read error", logfields.Error, err)
				continue
			}

			pktime, err = proc.GetStatsKtime(pstats)
			if err != nil {
				logger.GetLogger().Warn("parent ktime read error", logfields.Error, err)
			}

			if dockerID != "" {
				// We have a container ID so let's get the nspid inside.
				pnspid, _, _, _ = caps.GetPIDCaps(filepath.Join(procPath, ppid, "status"))
			}
		} else {
			pcmdline = nil
			pstats = nil
			pktime = 0
			pnspid = 0
		}

		execPath, err := os.Readlink(filepath.Join(procPath, d.Name(), "exe"))
		if err != nil {
			if kernelThread {
				execPath = strings.TrimSuffix(string(cmdline), "\n")
			} else {
				logger.GetLogger().Warn("reading process exe error", "process", d.Name(), logfields.Error, err)
			}
		}

		if _ppid != 0 {
			pexecPath, err = os.Readlink(filepath.Join(procPath, ppid, "exe"))
			if err != nil {
				if kernelThread {
					pexecPath = strings.TrimSuffix(string(pcmdline), "\n")
				} else {
					logger.GetLogger().Warn("reading process exe error", "process", ppid, logfields.Error, err)
				}
			}
		} else {
			pexecPath = ""
		}

		p := procs{
			ppid:                 uint32(_ppid),
			pnspid:               pnspid,
			pexe:                 stringToUTF8([]byte(pexecPath)),
			pcmdline:             stringToUTF8(pcmdline),
			pflags:               api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			pktime:               pktime,
			uids:                 uids,
			gids:                 gids,
			auid:                 auid,
			pid:                  uint32(pid),
			tid:                  uint32(pid), // Read dir does not return threads and we only track tgid
			nspid:                nspid,
			exe:                  stringToUTF8([]byte(execPath)),
			cmdline:              stringToUTF8(cmdline),
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
			kernel_thread:        kernelThread,
		}

		p.size = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.args()) + processapi.MSG_SIZEOF_CWD)
		p.psize = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.pargs()) + processapi.MSG_SIZEOF_CWD)

		processes = append(processes, p)
	}

	logger.GetLogger().Info(fmt.Sprintf("Read ProcFS %s appended %d/%d entries", option.Config.ProcFS, len(processes), len(procFS)))

	return processes, nil
}
