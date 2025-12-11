// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/pidfile"

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
	COMMAND_MAX_SIZE               = ((64 * 1024) - 32)
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
	QueryPerformanceCounter          = ModuleKernel32.NewProc("QueryPerformanceCounter")
	QueryPerformanceFrequency        = ModuleKernel32.NewProc("QueryPerformanceFrequency")
	GetSysTimeAsFileTime             = ModuleKernel32.NewProc("GetSystemTimeAsFileTime")
	GetTickCount64                   = ModuleKernel32.NewProc("GetTickCount64")
	bootTimeEpoch                    = GetBootTimeInWindowsEpoch()

	system = procs{
		ppid:         4,
		pnspid:       0,
		pexe:         stringToUTF8([]byte("<kernel>")),
		pcmdline:     stringToUTF8([]byte("<kernel>")),
		pflags:       api.EventProcFS | api.EventNeedsCWD,
		pktime:       bootTimeEpoch,
		pid:          4,
		tid:          4,
		nspid:        0,
		exe:          stringToUTF8([]byte("system")),
		cmdline:      stringToUTF8([]byte("system")),
		flags:        api.EventProcFS | api.EventNeedsCWD,
		ktime:        bootTimeEpoch,
		kernelThread: true,
	}
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

type SystemInfo struct {
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

func getBootTimeNanoseconds() uint64 {
	var freq, counter uint64
	QueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&freq)))
	if freq == 0 {
		ticks, _, _ := GetTickCount64.Call()
		counter = uint64(ticks)
		freq = 1000
	} else {
		QueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&counter)))
	}
	multiplier := float64(10000000000) / float64(freq)
	return uint64(float64(counter) * multiplier)
}

func GetSystemTimeAsFileTime() windows.Filetime {
	var ft windows.Filetime
	GetSysTimeAsFileTime.Call(uintptr(unsafe.Pointer(&ft)))
	return ft
}

// This function returns the value of system boot in 100 NS since 1600
func GetBootTimeInWindowsEpoch() uint64 {
	ft := GetSystemTimeAsFileTime()
	kTime := uint64((int64(ft.HighDateTime) << 32) + int64(ft.LowDateTime))
	var bootTime uint64
	QueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&bootTime)))
	bTime := getBootTimeNanoseconds()
	return (kTime - (bTime / 1000))

}

func KTimeToWindowsEpoch(ktime uint64) uint64 {
	return (ktime/100 + bootTimeEpoch)
}

func convertUTF16ToString(src []byte) string {
	srcLen := len(src) / 2

	codePoints := make([]uint16, srcLen)

	srcIdx := 0
	for i := range srcLen {
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

func U16ToBytes(u []uint16) []byte {
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[2*i] = byte(v)
		b[2*i+1] = byte(v >> 8)
	}
	return b
}

func writeExecveMap(procs []procs) map[uint32]struct{} {

	retMap := make(map[uint32]struct{})
	// on Windows we use a different map atructure.
	// There are two maps, one for commandline and another for image path
	// We update both for existing processes here.
	coll, _ := bpf.GetCollection("ProcessMonitor")

	if coll == nil {
		return retMap
	}
	var ok bool
	cmdMap, ok := coll.Maps["command_map"]
	if !ok {
		return retMap
	}
	imageMap, ok := coll.Maps["process_map"]
	if !ok {
		return retMap
	}
	var err error
	for _, p := range procs {
		if p.exe != nil {
			var imagePathBuf [1024]byte
			imagePath := "\\??\\" + string(p.exe)
			wideImagePath, _ := windows.UTF16FromString(imagePath)
			copy(imagePathBuf[:], U16ToBytes(wideImagePath))
			err = imageMap.Put(p.pid, imagePathBuf)
			if err != nil {
				logger.GetLogger().Warn("Failed writing imagePath to cmdMap", logfields.Error, err)
			}
		}
		if p.cmdline != nil {
			var cmdLineBuf [COMMAND_MAX_SIZE]byte
			wideCmdLine, _ := windows.UTF16FromString(string(p.cmdline))
			copy(cmdLineBuf[:], U16ToBytes(wideCmdLine))
			err = cmdMap.Put(p.pid, cmdLineBuf)
			if err != nil {
				logger.GetLogger().Warn("Failed writing cmdLine to cmdMap", logfields.Error, err)
			}
		}
	}
	return retMap
}

func getProcessParamsFromHandle64(handle windows.Handle) (RtlUserProcessParams64, error) {
	pebAddress, err := queryPebAddress(syscall.Handle(handle), false)
	if err != nil {
		return RtlUserProcessParams64{}, fmt.Errorf("cannot locate process PEB: %w", err)
	}

	buf := readProcessMemory(syscall.Handle(handle), false, pebAddress, uint(unsafe.Sizeof(PEB64{})))
	if len(buf) != int(unsafe.Sizeof(PEB64{})) {
		return RtlUserProcessParams64{}, errors.New("cannot read process PEB")
	}
	peb := (*PEB64)(unsafe.Pointer(&buf[0]))
	buf = readProcessMemory(syscall.Handle(handle), false, peb.ProcessParameters, uint(unsafe.Sizeof(RtlUserProcessParams64{})))
	if len(buf) != int(unsafe.Sizeof(RtlUserProcessParams64{})) {
		return RtlUserProcessParams64{}, errors.New("cannot read user process parameters")
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
		return RtlUserProcessParams32{}, errors.New("cannot read process PEB")
	}
	peb := (*PEB32)(unsafe.Pointer(&buf[0]))
	buf = readProcessMemory(syscall.Handle(handle), true, uint64(peb.ProcessParameters), uint(unsafe.Sizeof(RtlUserProcessParams32{})))
	if len(buf) != int(unsafe.Sizeof(RtlUserProcessParams32{})) {
		return RtlUserProcessParams32{}, errors.New("cannot read user process parameters")
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
		}
		return 0, windows.NTStatus(ret)
	}
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
	}
	return 0, windows.NTStatus(ret)
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
	var systemInfo SystemInfo
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
		return strings.ToLower(windows.UTF16ToString(buf[:])), nil
	}
	return "", errors.New("could not find function QueryFullProcessImageNameW")
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

// nolint:revive
func NewProcess(procEntry windows.ProcessEntry32) (procs, error) {
	var empty procs
	var pcmdline string
	var cmdline string
	var ktime uint64
	var pktime uint64
	var pid = procEntry.ProcessID
	var ppid = procEntry.ParentProcessID
	var execPath = windows.UTF16ToString(procEntry.ExeFile[:])
	var origExecPath = execPath
	var pexecPath string
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		logger.GetLogger().Warn(fmt.Sprintf("Failed Opening Process %d (%s)", pid, execPath), logfields.Error, err)
		if pid == 0 {
			// If pid is 0, we are looking at the kernel process, so we return empty
			return empty, err
		}
		if pid == 4 {
			// If pid is 4, we are looking at the system process, Opening which will fail, so we return hardcoded fields.
			return system, nil
		}
		hProc, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Failed Opening Process with limited privileges %d (%s)", pid, execPath), logfields.Error, err)
			return empty, err
		}
	}
	defer windows.CloseHandle(hProc)
	execPath, err = getProcessImagePathFromHandle(hProc)
	if err != nil {
		logger.GetLogger().Warn("Reading process path error", logfields.Error, err)
		execPath = origExecPath
	}
	cmdline, err = fetchProcessCmdLineFromHandle(hProc)
	if err != nil {
		logger.GetLogger().Warn("Reading process cmdline error", logfields.Error, err)
		cmdline = execPath

	}

	times, err := getProcessTimesFromHandle(hProc)
	if err != nil {
		logger.GetLogger().Warn("Reading process times error", logfields.Error, err)
		ktime = bootTimeEpoch
	} else {
		ct := times.CreationTime
		ktime = uint64((int64(ct.HighDateTime) << 32) + int64(ct.LowDateTime))
	}

	// Initialize with invalid uid
	uids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
	gids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
	auid := proc.InvalidUid
	// Get process status
	status, err := proc.GetStatusFromHandle(hProc)
	if err != nil {
		logger.GetLogger().Warn("Reading process status error", logfields.Error, err)
	} else {
		uids, err = status.GetUids()
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Reading Uids of %d failed, falling back to uid: %d", pid, uint32(proc.InvalidUid)), logfields.Error, err)
		}
		gids, err = status.GetGids()
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Reading Uids of %d failed, falling back to gid: %d", pid, uint32(proc.InvalidUid)), logfields.Error, err)
		}

		auid, err = status.GetLoginUid()
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Reading Loginuid of %d failed, falling back to loginuid: %d", pid, uint32(auid)), logfields.Error, err)
		}

	}
	// ToDo: In Windows, there is no namespace.
	// The Capabilities are generally privileges which are LUIDs.
	// found using GetTokenInformation with TokenPrivileges, and converted o string using LookupPrivilegeName.
	// They are best expressed as an array of strings, and don't fit in current structure.
	var permitted, effective, inheritable uint64
	var nsPID, utsNs, ipcNs, mntNs, pidNs, pidForChildrenNs uint32

	var netNs, timeNs uint32
	var timeForChildrenNs uint32

	var cgroupNs, userNs uint32
	pcmdline = ""
	pktime = 0
	var pnspid uint32
	if ppid != 0 {
		hPProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(ppid))
		if err != nil {
			hPProc, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(ppid))
		}
		if (err == nil) && (pidfile.IsPidAliveByHandle(hPProc)) {

			defer windows.CloseHandle(hPProc)
			pcmdline, err = fetchProcessCmdLineFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().Warn("Reading parent process cmdline error", logfields.Error, err)
			}
			ptimes, err := getProcessTimesFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().Warn("Reading parent process times error", logfields.Error, err)
			} else {
				pktime = uint64(ptimes.CreationTime.Nanoseconds())
			}
			pexecPath, err = getProcessImagePathFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().Warn("Reading parent process image path error", logfields.Error, err)
			}
		} else {
			logger.GetLogger().Warn(fmt.Sprintf("Failed Opening Parent Process %d", ppid), logfields.Error, err)
			ppid = 4
		}
	}

	p := procs{
		ppid:              uint32(ppid),
		pnspid:            pnspid,
		pexe:              stringToUTF8([]byte(pexecPath)),
		pcmdline:          stringToUTF8([]byte(pcmdline)),
		pflags:            api.EventProcFS | api.EventNeedsCWD,
		pktime:            pktime,
		uids:              uids,
		gids:              gids,
		auid:              auid,
		pid:               uint32(pid),
		tid:               uint32(pid), // Read dir does not return threads and we only track tgid
		nspid:             nsPID,
		exe:               stringToUTF8([]byte(execPath)),
		cmdline:           stringToUTF8([]byte(cmdline)),
		flags:             api.EventProcFS | api.EventNeedsCWD,
		ktime:             ktime,
		permitted:         permitted,
		effective:         effective,
		inheritable:       inheritable,
		utsNs:             utsNs,
		ipcNs:             ipcNs,
		mntNs:             mntNs,
		pidNs:             pidNs,
		pidForChildrenNs:  pidForChildrenNs,
		netNs:             netNs,
		timeNs:            timeNs,
		timeForChildrenNs: timeForChildrenNs,
		cgroupNs:          cgroupNs,
		userNs:            userNs,
		kernelThread:      false,
	}

	p.size = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.args()) + processapi.MSG_SIZEOF_CWD)
	p.psize = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.pargs()) + processapi.MSG_SIZEOF_CWD)
	return p, nil

}

func listRunningProcs(_ string) ([]procs, error) {
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

	logger.GetLogger().Info(fmt.Sprintf("Read process list appended %d entries", len(processes)))
	return processes, nil
}
