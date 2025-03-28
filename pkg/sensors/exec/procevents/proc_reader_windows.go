// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
)

type ProcessBasicInfo64 struct {
	ExitStatus                   uint64
	PebBaseAddress               uint64
	AffinityMask                 uint64
	BasePriority                 uint64
	UniqueProcessId              uint64
	InheritedFromUniqueProcessId uint64
}

type PEB32 struct {
	Reserved1         [2]uint8
	BeingDebugged     uint8
	Reserved2         uint8
	Reserved3         [2]uint32
	Ldr               uint32
	ProcessParameters uint32
	Reserved4         [3]uint32
	AltThunkListPtr   uint32
	Reserved5         [4]uint32
	//--unused--
}

type PEB64 struct {
	Reserved1         [2]uint8
	BeingDebugged     uint8
	Reserved2         [5]uint8
	Reserved3         [2]uint64
	Ldr               uint64
	ProcessParameters uint64
	Reserved4         [3]uint64
	AltThunkListPtr   uint64
	Reserved5         [4]uint64
	//--unused--
}

const (
	PROCESSOR_ARCHITECTURE_AMD64   = 9      //x64 (AMD or Intel)
	PROCESSOR_ARCHITECTURE_ARM     = 5      //ARM
	PROCESSOR_ARCHITECTURE_ARM64   = 12     // ARM64
	PROCESSOR_ARCHITECTURE_IA64    = 6      //Intel Itanium-based
	PROCESSOR_ARCHITECTURE_INTEL   = 0      //x86
	PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff //Unknown arc
)

var (
	ModuleNt                         = windows.NewLazySystemDLL("ntdll.dll")
	ModuleKernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	NtQuerySystemInformation         = ModuleNt.NewProc("NtQuerySystemInformation")
	RtlGetNativeSystemInformation    = ModuleNt.NewProc("RtlGetNativeSystemInformation")
	RtlNtStatusToDosError            = ModuleNt.NewProc("RtlNtStatusToDosError")
	NtQueryInformationProcess        = ModuleNt.NewProc("NtQueryInformationProcess")
	NtReadVirtualMemory              = ModuleNt.NewProc("NtReadVirtualMemory")
	NtWow64QueryInformationProcess64 = ModuleNt.NewProc("NtWow64QueryInformationProcess64")
	NtWow64ReadVirtualMemory64       = ModuleNt.NewProc("NtWow64ReadVirtualMemory64")
	QueryFullProcessImageNameW       = ModuleKernel32.NewProc("QueryFullProcessImageNameW")
	QueryDosDeviceW                  = ModuleKernel32.NewProc("QueryDosDeviceW")
	GetSystemInfo                    = ModuleKernel32.NewProc("GetSystemInfo")

	processorArch uint
)

type UnicodeString32 struct {
	Length        uint16
	MaximumLength uint16
	Buf           uint32
}

type UnicodeString64 struct {
	Length        uint16
	MaximumLength uint16
	Buf           uint64
}

type RtlUserProcessParams32 struct {
	Reserved1     [16]uint8
	Reserved2     [10]uint32
	ImagePathName UnicodeString32
	CommandLine   UnicodeString32
}

type RtlUserProcessParams64 struct {
	Reserved1     [16]uint8
	Reserved2     [10]uint64
	ImagePathName UnicodeString64
	CommandLine   UnicodeString64
}

type SYSTEM_INFO struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

func convertUTF16ToString(src []byte) string {
	srcLen := len(src) / 2

	codePoints := make([]uint16, srcLen)

	srcIdx := 0
	for i := 0; i < srcLen; i++ {
		codePoints[i] = uint16(src[srcIdx]) | uint16(src[srcIdx+1])<<8
		srcIdx += 2
	}
	return syscall.UTF16ToString(codePoints)
}

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
		auid:        proc.InvalidUid,
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

func updateExecveMapStats(procs int64) {
	//ToDo: WIP
	// Currently we do not share the infor gathered in usermode with execve map in kernel in Windows,
	// This method is currently stubbed out but will be implemented

}

func writeExecveMap(procs []procs) {
	//ToDo: WIP
	// Currently we do not share the infor gathered in usermode with execve map in kernel in Windows,
	// This method is currently stubbed out but will be implemented
}

func getProcessParamsFromHandle64(handle windows.Handle) (RtlUserProcessParams64, error) {
	pebAddress, err := queryPebAddress(syscall.Handle(handle), false)
	if err != nil {
		return RtlUserProcessParams64{}, fmt.Errorf("cannot locate process PEB: %w", err)
	}

	buf := readProcessMemory(syscall.Handle(handle), false, pebAddress, uint(unsafe.Sizeof(PEB64{})))
	if len(buf) != int(unsafe.Sizeof(PEB64{})) {
		return RtlUserProcessParams64{}, fmt.Errorf("cannot read process PEB")
	}
	peb := (*PEB64)(unsafe.Pointer(&buf[0]))
	buf = readProcessMemory(syscall.Handle(handle), false, peb.ProcessParameters, uint(unsafe.Sizeof(RtlUserProcessParams64{})))
	if len(buf) != int(unsafe.Sizeof(RtlUserProcessParams64{})) {
		return RtlUserProcessParams64{}, fmt.Errorf("cannot read user process parameters")
	}
	return *(*RtlUserProcessParams64)(unsafe.Pointer(&buf[0])), nil
}

func getProcessParamsFromHandle32(handle windows.Handle) (RtlUserProcessParams32, error) {
	pebAddress, err := queryPebAddress(syscall.Handle(handle), true)
	if err != nil {
		return RtlUserProcessParams32{}, fmt.Errorf("cannot locate process PEB: %w", err)
	}

	buf := readProcessMemory(syscall.Handle(handle), true, pebAddress, uint(unsafe.Sizeof(PEB32{})))
	if len(buf) != int(unsafe.Sizeof(PEB32{})) {
		return RtlUserProcessParams32{}, fmt.Errorf("cannot read process PEB")
	}
	peb := (*PEB32)(unsafe.Pointer(&buf[0]))
	buf = readProcessMemory(syscall.Handle(handle), true, uint64(peb.ProcessParameters), uint(unsafe.Sizeof(RtlUserProcessParams32{})))
	if len(buf) != int(unsafe.Sizeof(RtlUserProcessParams32{})) {
		return RtlUserProcessParams32{}, fmt.Errorf("cannot read user process parameters")
	}
	return *(*RtlUserProcessParams32)(unsafe.Pointer(&buf[0])), nil
}

func getProcessTimesFromHandle(hProc windows.Handle) (windows.Rusage, error) {
	var times windows.Rusage

	if err := windows.GetProcessTimes(hProc, &times.CreationTime, &times.ExitTime, &times.KernelTime, &times.UserTime); err != nil {
		return times, err
	}

	return times, nil
}

// ToDo: Test the 32 bit piece for wow64 processes
func queryPebAddress(procHandle syscall.Handle, is32BitProcess bool) (uint64, error) {
	if is32BitProcess {
		//we are on a 64-bit process reading an external 32-bit process
		var wow64 uint

		ret, _, _ := NtQueryInformationProcess.Call(
			uintptr(procHandle),
			uintptr(windows.ProcessWow64Information),
			uintptr(unsafe.Pointer(&wow64)),
			uintptr(unsafe.Sizeof(wow64)),
			uintptr(0),
		)
		if status := windows.NTStatus(ret); status == windows.STATUS_SUCCESS {
			return uint64(wow64), nil
		} else {
			return 0, windows.NTStatus(ret)
		}
	} else {
		//we are on a 64-bit process reading an external 64-bit process
		var info ProcessBasicInfo64

		ret, _, _ := NtQueryInformationProcess.Call(
			uintptr(procHandle),
			uintptr(windows.ProcessBasicInformation),
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Sizeof(info)),
			uintptr(0),
		)
		if status := windows.NTStatus(ret); status == windows.STATUS_SUCCESS {
			return info.PebBaseAddress, nil
		} else {
			return 0, windows.NTStatus(ret)
		}
	}
}

func readProcessMemory(procHandle syscall.Handle, _ bool, address uint64, size uint) []byte {
	var bytesRead uint

	buf := make([]byte, size)

	ret, _, _ := NtReadVirtualMemory.Call(
		uintptr(procHandle),
		uintptr(address),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if int(ret) >= 0 && bytesRead > 0 {
		return buf[:bytesRead]
	}
	return nil
}

func init() {
	var systemInfo SYSTEM_INFO
	GetSystemInfo.Call(uintptr(unsafe.Pointer(&systemInfo)))
	processorArch = uint(systemInfo.wProcessorArchitecture)
}

func isProcess32Bit(h windows.Handle) bool {

	var wow64Process uint
	is2Bit := (unsafe.Sizeof(wow64Process) == 4)
	switch processorArch {
	// We ned to check only for 32 bit processes running on x64 machines
	case PROCESSOR_ARCHITECTURE_ARM64:
		fallthrough
	case PROCESSOR_ARCHITECTURE_IA64:
		fallthrough
	case PROCESSOR_ARCHITECTURE_AMD64:
		ret, _, _ := NtQueryInformationProcess.Call(
			uintptr(h),
			uintptr(windows.ProcessWow64Information),
			uintptr(unsafe.Pointer(&wow64Process)),
			uintptr(unsafe.Sizeof(wow64Process)),
			uintptr(0),
		)
		if (ret > 0) && (wow64Process != 0) {
			is2Bit = true
		}
	}
	return is2Bit
}

func getProcessImagePathFromHandle(hProc windows.Handle) (string, error) {
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(syscall.MAX_LONG_PATH)
	if err := QueryFullProcessImageNameW.Find(); err == nil {
		ret, _, err := QueryFullProcessImageNameW.Call(
			uintptr(hProc),
			uintptr(0),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)))
		if ret == 0 {
			return "", err
		}
		return windows.UTF16ToString(buf[:]), nil
	}
	return "", fmt.Errorf("Could not find function QueryFullProcessImageNameW")
}

func fetchProcessCmdLineFromHandle(hProc windows.Handle) (string, error) {

	is32Bit := isProcess32Bit(hProc)

	if is32Bit {
		procParams32, paramsErr := getProcessParamsFromHandle32(hProc)
		if paramsErr != nil {
			return "", paramsErr
		}
		if procParams32.CommandLine.Length > 0 {
			commandLine := readProcessMemory(syscall.Handle(hProc), is32Bit, uint64(procParams32.CommandLine.Buf), uint(procParams32.CommandLine.Length))
			if len(commandLine) != int(procParams32.CommandLine.Length) {
				return "", errors.New("cannot read command line")
			}

			return convertUTF16ToString(commandLine), nil
		}
	} else {
		procParams64, paramsErr := getProcessParamsFromHandle64(hProc)
		if paramsErr != nil {
			return "", paramsErr
		}
		if procParams64.CommandLine.Length > 0 {
			commandLine := readProcessMemory(syscall.Handle(hProc), is32Bit, procParams64.CommandLine.Buf, uint(procParams64.CommandLine.Length))
			if len(commandLine) != int(procParams64.CommandLine.Length) {
				return "", errors.New("cannot read command line")
			}

			return convertUTF16ToString(commandLine), nil
		}
	}
	return "", nil
}

func NewProcess(procEntry windows.ProcessEntry32) (procs, error) {
	var empty procs
	var pcmdline string
	var cmdline string
	var ktime uint64
	var pktime uint64
	var pid uint32 = procEntry.ProcessID
	var ppid uint32 = procEntry.ParentProcessID
	var execPath string = windows.UTF16ToString(procEntry.ExeFile[:])
	var pexecPath string
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed Opening Process %d (%s)", pid, execPath)
		return empty, err
	}
	defer windows.CloseHandle(hProc)
	execPath, err = getProcessImagePathFromHandle(hProc)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Reading process path error")
		return empty, err
	}
	cmdline, err = fetchProcessCmdLineFromHandle(hProc)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Reading process cmdline error")
	}
	times, err := getProcessTimesFromHandle(hProc)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Reading process times error")
	}
	ktime = uint64(times.CreationTime.Nanoseconds())
	// Initialize with invalid uid
	uids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
	gids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
	auid := proc.InvalidUid
	// Get process status
	status, err := proc.GetStatusFromHandle(hProc)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Reading process status error")
	} else {
		uids, err = status.GetUids()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Reading Uids of %d failed, falling back to uid: %d", pid, uint32(proc.InvalidUid))
		}

		gids, err = status.GetGids()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Reading Uids of %d failed, falling back to gid: %d", pid, uint32(proc.InvalidUid))
		}

		auid, err = status.GetLoginUid()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Reading Loginuid of %d failed, falling back to loginuid: %d", pid, uint32(auid))
		}
	}
	// ToDo: In Windows, there is no namespace.
	// The Capabilities are generally privileges which are LUIDs.
	// found using GetTokenInformation with TokenPrivileges, and converted o string using LookupPrivilegeName.
	// They are best expressed as an array of strings, and don't fit in current structure.
	var permitted, effective, inheritable uint64
	var nspid, uts_ns, ipc_ns, mnt_ns, pid_ns, pid_for_children_ns uint32

	var net_ns, time_ns uint32
	var time_for_children_ns uint32

	var cgroup_ns, user_ns uint32
	pcmdline = ""
	pktime = 0
	var pnspid uint32
	if ppid != 0 {
		hPProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(ppid))
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Failed Opening Parent Process %d", ppid)
		} else {
			defer windows.CloseHandle(hPProc)
			pcmdline, err = fetchProcessCmdLineFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading parent process cmdline error")
			}
			ptimes, err := getProcessTimesFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading parent process times error")
			}
			pktime = uint64(ptimes.CreationTime.Nanoseconds())
			pexecPath, err = getProcessImagePathFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading parent process image path error")
			}
		}
	}

	p := procs{
		ppid:                 uint32(ppid),
		pnspid:               pnspid,
		pexe:                 stringToUTF8([]byte(pexecPath)),
		pcmdline:             stringToUTF8([]byte(pcmdline)),
		pflags:               api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
		pktime:               pktime,
		uids:                 uids,
		gids:                 gids,
		auid:                 auid,
		pid:                  uint32(pid),
		tid:                  uint32(pid), // Read dir does not return threads and we only track tgid
		nspid:                nspid,
		exe:                  stringToUTF8([]byte(execPath)),
		cmdline:              stringToUTF8([]byte(cmdline)),
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
		kernel_thread:        false,
	}

	p.size = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.args()) + processapi.MSG_SIZEOF_CWD)
	p.psize = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.pargs()) + processapi.MSG_SIZEOF_CWD)
	return p, nil

}

func listRunningProcs(procPath string) ([]procs, error) {
	var processes []procs
	snapshotHandle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, uint32(0))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshotHandle)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err := windows.Process32First(snapshotHandle, &procEntry); err != nil {
		return nil, err
	}

	for {
		p, err := NewProcess(procEntry)
		if err == nil {
			processes = append(processes, p)
		}
		if err = windows.Process32Next(snapshotHandle, &procEntry); err != nil {
			break
		}

	}

	logger.GetLogger().Infof("Read process list appended %d entries", len(processes))
	return processes, nil
}
