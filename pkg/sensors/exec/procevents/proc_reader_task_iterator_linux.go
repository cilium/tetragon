// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
)

const (
	ProcScanKthread  = 0x1
	ProcScanCwdError = 0x2
	// ProcScanNotInMap is set if the process could not be added to
	// execve_map, i.e. the map is full.
	ProcScanNotInMap = 0x4

	procScanCwdMax = 4096
)

// ProcScanEntry mirrors struct proc_scan_entry in bpf/process/bpf_proc_scan.c
type ProcScanEntry struct {
	Pid    uint32
	Flags  uint32
	Ktime  uint64
	Uids   [4]uint32
	Gids   [4]uint32
	Auid   uint32
	CwdLen uint32
	Kube   processapi.MsgK8s
	Cwd    [procScanCwdMax]byte
}

// RunProcScan returns the processes found by the proc_scan program, which
// also adds them to execve_map. It returns false if the program is not
// enabled, not loaded or failed. The program and its map are unloaded once
// done to free resources, so later calls return false and the caller can fall back to procfs if needed.
// Note however that we only need a single call during startup.
func RunProcScan() ([]ProcScanEntry, bool, error) {
	if !base.BPFProcScanEnabled() || base.BpfProcScanMap.MapHandle == nil {
		return nil, false, nil
	}
	entries, err := procScan()
	return entries, err == nil, err
}

func procScan() ([]ProcScanEntry, error) {
	// The program and its map are only needed once.
	defer unloadProcScan()

	m := base.BpfProcScanMap.MapHandle
	cnt, err := base.BpfProcScan.Prog.Run(&ebpf.RunOptions{})
	if err != nil {
		return nil, fmt.Errorf("running proc_scan program failed: %w", err)
	}

	entries := make([]ProcScanEntry, 0, cnt)
	for i := range cnt {
		var e ProcScanEntry

		if err := m.Lookup(i, &e); err != nil {
			logger.GetLogger().Warn("Failed to read proc_scan entry", "index", i, logfields.Error, err)
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// unloadProcScan releases the proc_scan program and map. The base sensor
// unload skips them afterwards, as they are no longer loaded.
func unloadProcScan() {
	if err := base.BpfProcScan.Unload(true); err != nil {
		logger.GetLogger().Warn("Failed to unload proc_scan program", logfields.Error, err)
	}
	if err := base.BpfProcScanMap.Unload(true); err != nil {
		logger.GetLogger().Warn("Failed to unload proc_scan map", logfields.Error, err)
	}
}

// scanRunningProcs lists the running processes found by the proc_scan BPF
// program, which also adds them to execve_map. It returns false if the
// program is not available or failed, in which case the caller should fall
// back to the procfs scan.
//
// Unlike the procfs scan, existing execve_map entries are not overwritten:
// those were added by the exec and fork hooks since they were loaded, which
// also reported the processes.
func scanRunningProcs(procPath string) ([]procs, map[uint32]struct{}, bool, error) {
	entries, ok, err := RunProcScan()
	if !ok {
		return nil, nil, false, err
	}

	m := openExecveMap()
	defer m.Close()

	processes := make([]procs, 0, len(entries))
	inInitTree := make(map[uint32]struct{})
	var w readProcWarnings
	for i := range entries {
		e := &entries[i]
		var v execvemap.ExecveValue

		if e.Flags&ProcScanNotInMap != 0 {
			p, ok := readProc(procPath, strconv.FormatUint(uint64(e.Pid), 10), &w)
			// The process exited, possibly with its pid reused.
			if !ok || p.ktime != e.Ktime {
				continue
			}
			// Same as procToKeyValue()
			if _, ok := inInitTree[p.ppid]; ok || p.nspid == 1 {
				inInitTree[p.pid] = struct{}{}
			}
			processes = append(processes, p)
			continue
		}

		// The process exited, or exec-ed and was already reported by
		// the exec hook.
		if err := m.Lookup(&execvemap.ExecveKey{Pid: e.Pid}, &v); err != nil || v.Process.Ktime != e.Ktime {
			continue
		}
		if v.Flags&api.EventInInitTree != 0 {
			inInitTree[e.Pid] = struct{}{}
		}
		processes = append(processes, procFromScan(procPath, m, e, &v))
	}
	writeExecveMapKernel(m)

	logger.GetLogger().Info(fmt.Sprintf("BPF process scan appended %d/%d entries", len(processes), len(entries)))

	return processes, inInitTree, true, nil
}

// procFromScan builds the procs entry of a process found by the BPF scan so
// that the startup event matches the one of the procfs scan. The binary path
// and the arguments in execve_map are truncated, so the full ones are read
// from procfs.
func procFromScan(procPath string, m *ebpf.Map, e *ProcScanEntry, v *execvemap.ExecveValue) procs {
	pidstr := strconv.FormatUint(uint64(e.Pid), 10)
	kernelThread := e.Flags&ProcScanKthread != 0

	var exe []byte
	if v.Binary.PathLength > 0 {
		exe = v.Binary.Path[:min(int(v.Binary.PathLength), len(v.Binary.Path))]
	}

	var cmdline []byte
	if !kernelThread {
		if execPath, err := os.Readlink(filepath.Join(procPath, pidstr, "exe")); err == nil {
			exe = []byte(execPath)
		}
		var err error
		cmdline, err = os.ReadFile(filepath.Join(procPath, pidstr, "cmdline"))
		if err != nil || len(cmdline) == 0 {
			// execve_map args exclude argv[0], which is not used
			// anyway as it's resolved as the filename.
			cmdline = append([]byte{0}, v.Args.Buf[:min(int(v.Args.Len), len(v.Args.Buf))]...)
		}
	}

	// Same flags as getCWD(), an empty path is the root directory.
	var cwd string
	var cwdFlags uint32
	if e.Flags&ProcScanCwdError != 0 {
		cwdFlags = api.EventRootCWD | api.EventErrorCWD
	} else if e.CwdLen == 0 {
		cwd = "/"
	} else {
		cwd = string(e.Cwd[:min(int(e.CwdLen), len(e.Cwd))])
	}

	// Same as the exec events, see msgToExecveKubeUnix().
	var dockerId string
	if e.Kube.Docker[0] != 0x00 {
		cgroup := cgroups.CgroupNameFromCStr(e.Kube.Docker[:processapi.CGROUP_NAME_LENGTH])
		dockerId, _ = LookupContainerId(cgroup, true, false)
	}

	// The procfs scan sets nspid and the cgroup id only for processes in
	// containers, the former to construct the pod information. It reads
	// nspid from /proc/<pid>/status, which reports the pid itself for
	// processes in the initial pid namespace.
	var nspid, pnspid uint32
	var cgrpid uint64
	if dockerId != "" {
		cgrpid = e.Kube.Cgrpid
		nspid = v.Nspid
		if nspid == 0 {
			nspid = e.Pid
		}
		if v.Parent.Pid != 0 {
			var pv execvemap.ExecveValue
			if err := m.Lookup(&execvemap.ExecveKey{Pid: v.Parent.Pid}, &pv); err == nil {
				pnspid = pv.Nspid
				if pnspid == 0 {
					pnspid = v.Parent.Pid
				}
			}
		}
	}

	return procs{
		ppid:              v.Parent.Pid,
		pnspid:            pnspid,
		pflags:            api.EventProcFS | api.EventNeedsCWD,
		pktime:            v.Parent.Ktime,
		uids:              e.Uids[:],
		gids:              e.Gids[:],
		auid:              e.Auid,
		pid:               e.Pid,
		tid:               e.Pid,
		nspid:             nspid,
		exe:               stringToUTF8(bytes.TrimRight(exe, "\x00")),
		cmdline:           stringToUTF8(cmdline),
		flags:             api.EventProcFS | api.EventNeedsCWD,
		ktime:             v.Process.Ktime,
		permitted:         v.Capabilities.Permitted,
		effective:         v.Capabilities.Effective,
		inheritable:       v.Capabilities.Inheritable,
		utsNs:             v.Namespaces.UtsInum,
		ipcNs:             v.Namespaces.IpcInum,
		mntNs:             v.Namespaces.MntInum,
		pidNs:             v.Namespaces.PidInum,
		pidForChildrenNs:  v.Namespaces.PidChildInum,
		netNs:             v.Namespaces.NetInum,
		timeNs:            v.Namespaces.TimeInum,
		timeForChildrenNs: v.Namespaces.TimeChildInum,
		cgroupNs:          v.Namespaces.CgroupInum,
		userNs:            v.Namespaces.UserInum,
		kernelThread:      kernelThread,
		scanned:           true,
		cwd:               cwd,
		cwdFlags:          cwdFlags,
		dockerId:          dockerId,
		cgrpid:            cgrpid,
	}
}
