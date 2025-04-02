// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"golang.org/x/sys/windows"
)

// process_info_t struct
type ProcessInfo struct {
	ProcessID         uint32
	ParentProcessID   uint32
	CreatingProcessID uint32
	CreatingThreadID  uint32
	CreationTime      uint64
	ExitTime          uint64
	ProcessExitCode   uint32
	Operation         uint8
}

// msg_process struct
type MsgProcess struct {
	Size       uint32
	PID        uint32
	TID        uint32
	NSPID      uint32
	SecureExec uint32
	UID        uint32
	AUID       uint32
	Flags      uint32
	INlink     uint32
	Pad        uint32
	IIno       uint64
	Ktime      uint64
	Args       [2048]byte // Adjust size as needed
}

// msg_k8s struct
type MsgK8s struct {
	Cgrpid        uint64
	CgrpTrackerID uint64
	DockerID      [128]byte
}

// msg_execve_key struct
type MsgExecveKey struct {
	PID   uint32
	Pad   [4]byte
	Ktime uint64
}

// msg_capabilities struct
type MsgCapabilities struct {
	Permitted   uint64
	Effective   uint64
	Inheritable uint64
}

// msg_user_namespace struct
type MsgUserNamespace struct {
	Level  int32
	UID    uint32
	GID    uint32
	NSInum uint32
}

// msg_cred struct
type MsgCred struct {
	UID        uint32
	GID        uint32
	SUID       uint32
	SGID       uint32
	EUID       uint32
	EGID       uint32
	FSUID      uint32
	FSGID      uint32
	SecureBits uint32
	Pad        uint32
	Caps       MsgCapabilities
	UserNS     MsgUserNamespace
}

// msg_ns struct
type MsgNS struct {
	UTSInum             uint32
	IPCInum             uint32
	MNTInum             uint32
	PIDInum             uint32
	PIDForChildrenInum  uint32
	NetInum             uint32
	TimeInum            uint32
	TimeForChildrenInum uint32
	CgroupInum          uint32
	UserInum            uint32
}

// msg_common struct
type MsgCommon struct {
	Op    uint8
	Flags uint8
	Pad   [2]byte
	Size  uint32
	Ktime uint64
}

// msg_execve_event struct
type MsgExecveEvent struct {
	Common      MsgCommon
	Kube        MsgK8s
	Parent      MsgExecveKey
	ParentFlags uint64
	Creds       MsgCred
	NS          MsgNS
	CleanupKey  MsgExecveKey
	Process     MsgProcess
	Buffer      [1024 + 256 + 56 + 56 + 256]byte
}

type ExitInfo struct {
	Code uint32
	Tid  uint32
}

type MsgExit struct {
	Common MsgCommon
	Curent MsgExecveKey
	Info   ExitInfo
}

type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	// Due to a kernel bug, this can contain between 0 and 7 bytes of trailing
	// garbage from the ring depending on the input sample's length.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64

	// The minimum number of bytes remaining in the per-CPU buffer after this Record has been read.
	// Negative for overwritable buffers.
	Remaining int
}

type RecordStruct struct {
	execEvent MsgExecveEvent
}

func getExitRecordFromProcInfo(process_info *bpf.ProcessInfo) (Record, error) {
	var record Record

	var exitEvent MsgExit
	exitEvent.Common.Op = ops.MSG_OP_EXIT
	exitEvent.Curent.PID = process_info.ProcessId
	exitEvent.Curent.Ktime = process_info.ExitTime
	exitEvent.Info.Code = process_info.ProcessExitCode
	exitEvent.Info.Tid = process_info.ProcessId
	record.RawSample = make([]byte, unsafe.Sizeof(exitEvent))
	record.CPU = 0
	copyBuf := unsafe.Slice((*byte)(unsafe.Pointer(&exitEvent)), unsafe.Sizeof(exitEvent))
	copy(record.RawSample, copyBuf)
	return record, nil
}

func getExecRecordFromProcInfo(process_info *bpf.ProcessInfo, command_map *ebpf.Map, imageMap *ebpf.Map) (Record, error) {
	// Create record struct
	var record Record

	var procEvent RecordStruct
	procEvent.execEvent.Common.Op = ops.MSG_OP_EXECVE
	procEvent.execEvent.Parent.PID = process_info.CreatingProcessId
	procEvent.execEvent.Process.PID = process_info.ProcessId
	procEvent.execEvent.Process.TID = process_info.ProcessId
	procEvent.execEvent.Process.Flags = 1
	procEvent.execEvent.Process.NSPID = 0
	procEvent.execEvent.Process.Size = uint32(unsafe.Offsetof(procEvent.execEvent.Process.Args))
	procEvent.execEvent.Process.Ktime = process_info.CreationTime

	var wideCmd [2048]uint16
	command_map.Lookup(process_info.ProcessId, &wideCmd)
	strCmd := windows.UTF16ToString(wideCmd[:])

	var wideImagePath [1024]byte
	imageMap.Lookup(process_info.ProcessId, &wideImagePath)
	var s *uint16
	s = (*uint16)(unsafe.Pointer(&wideImagePath[0]))
	strImagePath := windows.UTF16PtrToString(s)

	strImagePath += string(uint8(0))
	strImagePath += strCmd
	copy(procEvent.execEvent.Process.Args[:], strImagePath)
	procEvent.execEvent.Process.Size += uint32(len(strImagePath))

	bufSize := int(unsafe.Sizeof(procEvent)) + len(strImagePath)
	record.RawSample = make([]byte, bufSize)
	record.CPU = 0
	copyBuf := unsafe.Slice((*byte)(unsafe.Pointer(&procEvent)), bufSize)
	copy(record.RawSample, copyBuf)
	return record, nil
}

func (observer *Observer) RunEvents(stopCtx context.Context, ready func()) error {
	coll := bpf.GetExecCollection()
	if coll == nil {
		return fmt.Errorf("Exec Preloaded collection is nil")
	}
	commandline_map := coll.Maps["command_map"]
	ringBufMap := coll.Maps["process_ringbuf"]
	imageMap := coll.Maps["process_map"]
	reader := bpf.GetNewWindowsRingBufReader()
	err := reader.Init(ringBufMap.FD(), int(ringBufMap.MaxEntries()))
	if err != nil {
		return fmt.Errorf("Failed initing rinbuf reader", err)
	}
	// Inform caller that we're about to start processing events.
	observer.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through winEventsQueue channel.
	winEventsQueue := make(chan *Record, observer.getRBQueueSize())

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	observer.log.Info("Listening for events...")

	// Start reading records from the perf array. Reads until the reader is closed.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	go func() {
		defer wg.Done()
	}()

	go func() {
		defer wg.Done()

		for stopCtx.Err() == nil {
			var record Record
			procInfo, errCode := reader.GetNextProcess()
			if (errCode == bpf.ERR_RINGBUF_OFFSET_MISMATCH) || (errCode == bpf.ERR_RINGBUF_UNKNOWN_ERROR) {
				observer.log.WithField("NewError ", 0).WithError(err).Warn("Reading bpf events failed")
				break
			}
			if (errCode == bpf.ERR_RINGBUF_RECORD_DISCARDED) || (errCode == bpf.ERR_RINGBUF_TRY_AGAIN) {
				continue
			}
			if procInfo.Operation != 0 {
				record, err = getExitRecordFromProcInfo(procInfo)
			} else {
				record, err = getExecRecordFromProcInfo(procInfo, commandline_map, imageMap)
			}
			if err != nil {
				if stopCtx.Err() == nil {
					RingbufErrors.Inc()
					errorCnt := getCounterValue(RingbufErrors)
					observer.log.WithField("errors", errorCnt).WithError(err).Warn("Reading bpf events failed")
				}
			} else {
				if len(record.RawSample) > 0 {
					select {
					case winEventsQueue <- &record:
					default:
						// drop the event, since channel is full
						queueLost.Inc()
					}
					RingbufReceived.Inc()
				}
				if record.LostSamples > 0 {
					RingbufLost.Add(float64(record.LostSamples))
				}
			}
		}
	}()

	// Start processing records from ringbuffer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case winEvent := <-winEventsQueue:
				observer.receiveEvent(winEvent.RawSample)
				queueReceived.Inc()
			case <-stopCtx.Done():
				observer.log.WithError(stopCtx.Err()).Infof("Listening for events completed.")
				observer.log.Debugf("Unprocessed events in RB queue: %d", len(winEventsQueue))
				return
			}
		}
	}()

	// Loading default program consumes some memory lets kick GC to give
	// this back to the OS (K8s).
	go func() {
		runtime.GC()
	}()

	// Wait for context to be cancelled and then stop.
	<-stopCtx.Done()
	return nil
}
