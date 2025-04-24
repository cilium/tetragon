//go:build windows

package bpf

import (
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sys/windows"
)

var (
	ModuleNt       = windows.NewLazySystemDLL("ntdll.dll")
	ModuleKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	NtQuerySystemInformation = ModuleNt.NewProc("NtQuerySystemInformation")
	CreateFileW              = ModuleKernel32.NewProc("CreateFileW")
	DeviceIoControl          = ModuleKernel32.NewProc("DeviceIoControl")
	WaitForSingleObject      = ModuleKernel32.NewProc("WaitForSingleObject")
	CreateEventW             = ModuleKernel32.NewProc("CreateEventW")
	ResetEvent               = ModuleKernel32.NewProc("ResetEvent")
	GetModuleHandleW         = ModuleKernel32.NewProc("GetModuleHandleW")
	GetHandleFromFd          = EbpfApi.NewProc("ebpf_get_handle_from_fd")
	log                      = logger.GetLogger()
)

type operationHeader struct {
	length uint16
	id     uint32
}

type operationMapQueryBufferRequest struct {
	header    operationHeader
	mapHandle uint64
	index     uint32
}

type operationMapQueryBufferReply struct {
	header         operationHeader
	bufferAddress  uint64
	consumerOffset uint64
}

type operationMapAsyncQueryRequest struct {
	header         operationHeader
	mapHandle      uint64
	index          uint32
	consumerOffset uint64
}
type mapAsyncQueryResult struct {
	producer  uint64
	consumer  uint64
	lostCount uint64
}

type operationMapAsyncQueryReply struct {
	header           operationHeader
	asyncQueryResult mapAsyncQueryResult
}

type RingBufferRecord struct {
	length      uint32
	page_offset uint32
	data        [1]uint8
}

type ProcessInfo struct {
	ProcessId         uint32
	ParentProcessID   uint32
	CreatingProcessID uint32
	CreatingThreadID  uint32
	CreationTime      uint64
	ExitTime          uint64
	ProcessExitCode   uint32
	Operation         uint8
}

type GetOsfHandle func(fd int) uint32

var (
	errIOPending = error(syscall.Errno(windows.ERROR_IO_PENDING))
	errSuccess   = error(syscall.Errno(windows.ERROR_SUCCESS))
)

const (
	ERROR_SUCCESS                = 0
	ERROR_ACCESS_DENIED          = 5
	ERROR_INVALID_PARAMETER      = 87
	FILE_DEVICE_NETWORK          = 0x12
	FILE_ANY_ACCESS              = 0
	METHOD_BUFFERED              = 0
	INVALID_HANDLE_VALUE         = ^uintptr(0)
	EBPF_RINGBUF_LOCK_BIT        = uint32(1 << 31)
	EBPF_RINGBUF_DISCARD_BIT     = uint32(1 << 30)
	ERR_RINGBUF_OFFSET_MISMATCH  = 1
	ERR_RINGBUF_SUCCESS          = 0
	ERR_RINGBUF_TRY_AGAIN        = 2
	ERR_RINGBUF_RECORD_DISCARDED = 3
	ERR_RINGBUF_UNKNOWN_ERROR    = 4
	EBPF_OP_MAP_ASYNC_QUERY      = 29
	EBPF_OP_MAP_QUERY_BUF        = 28

	EBPF_IO_DEVICE = `\\.\EbpfIoDevice`
)

type WindowsRingBufReader struct {
	currRequest      operationMapAsyncQueryRequest
	producerOffset   uint64
	consumerOffset   uint64
	hSync            uintptr
	hASync           uintptr
	hOverlappedEvent uintptr
	ringBufferSize   uint64
	byteBuf          []byte
}

func GetNewWindowsRingBufReader() *WindowsRingBufReader {
	var reader WindowsRingBufReader
	reader.hASync = INVALID_HANDLE_VALUE
	reader.hSync = INVALID_HANDLE_VALUE
	reader.hOverlappedEvent = INVALID_HANDLE_VALUE
	reader.hOverlappedEvent, _ = CreateOverlappedEvent()
	return &reader
}

func CTLCode(DeviceType, Function, Method, Access uint32) uint32 {
	return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
}

func EbpfRingBufferRecordIsLocked(record *RingBufferRecord) bool {
	return atomic.LoadUint32(&record.length)&EBPF_RINGBUF_LOCK_BIT != 0
}

func EbpfRingBufferRecordIsDiscarded(record *RingBufferRecord) bool {
	return atomic.LoadUint32(&record.length)&EBPF_RINGBUF_DISCARD_BIT != 0
}

func EbpfRingBufferRecordLength(record *RingBufferRecord) uint32 {
	return (atomic.LoadUint32(&record.length)) & (uint32(^(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT)))
}

func EbpfRingBufferRecordTotalSize(record *RingBufferRecord) uint32 {
	return (EbpfRingBufferRecordLength(record) + uint32(unsafe.Offsetof(record.data)) + 7) & ^uint32(7)
}

func (reader *WindowsRingBufReader) invokeIoctl(request unsafe.Pointer, dwReqSize uint32, response unsafe.Pointer, dwRespSize uint32, overlapped unsafe.Pointer) error {
	var actualReplySize uint32
	var requestSize = dwReqSize
	var requestPtr = request
	var replySize = dwRespSize
	var replyPtr = response
	var variableReplySize = false
	var err error
	var hDevice = INVALID_HANDLE_VALUE

	if overlapped == nil {
		if reader.hSync == INVALID_HANDLE_VALUE {
			reader.hSync, _, err = CreateFileW.Call(
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(EBPF_IO_DEVICE))),
				uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
				0,
				0,
				uintptr(syscall.CREATE_ALWAYS),
				0,
				0,
			)
			if reader.hSync == INVALID_HANDLE_VALUE {
				return err
			}
			hDevice = reader.hSync
		}
	} else {
		if reader.hASync == INVALID_HANDLE_VALUE {
			reader.hASync, _, err = CreateFileW.Call(
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(EBPF_IO_DEVICE))),
				uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
				0,
				0,
				uintptr(syscall.CREATE_ALWAYS),
				uintptr(syscall.FILE_FLAG_OVERLAPPED),
				0,
			)
			if reader.hASync == INVALID_HANDLE_VALUE {
				return err
			}
		}
		hDevice = reader.hASync
	}
	if hDevice == INVALID_HANDLE_VALUE {
		return errors.New("error opening device")
	}
	success, _, err := DeviceIoControl.Call(
		uintptr(hDevice),
		uintptr(CTLCode(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)),
		uintptr(requestPtr),
		uintptr(requestSize),
		uintptr(replyPtr),
		uintptr(replySize),
		uintptr(unsafe.Pointer(&actualReplySize)),
		uintptr(overlapped),
	)
	if (overlapped != nil) && (success == 0) && (err == errIOPending) {
		success = 1
		err = nil
	}

	if success == 0 {
		log.WithError(syscall.GetLastError()).Error("device io control failed.")
		return err
	}

	if actualReplySize != replySize && !variableReplySize {
		return err
	}
	return nil

}
func CreateOverlappedEvent() (uintptr, error) {
	var err error
	var hEvent uintptr
	hEvent, _, err = CreateEventW.Call(0, 0, 0, 0)
	if err != error(syscall.Errno(0)) {
		log.WithError(err).Error("failed creating overlapped Event.")
		return INVALID_HANDLE_VALUE, err
	}
	ResetEvent.Call(hEvent)
	return hEvent, nil
}

func EbpfGetHandleFromFd(fd int) (uintptr, error) {
	var moduleHandle uintptr

	moduleHandle, _, err := GetModuleHandleW.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`ucrtbased.dll`))))
	if (err != errSuccess) || (moduleHandle == 0) {
		moduleHandle, _, err = GetModuleHandleW.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`ucrtbase.dll`))))
	}
	if (err != errSuccess) || (moduleHandle == 0) {
		log.WithError(err).Error("error getting ucrt base.")
		return 0, err
	}
	proc, err := syscall.GetProcAddress(syscall.Handle(moduleHandle), "_get_osfhandle")
	if (err != nil) || (proc == 0) {
		log.WithError(err).Error("error getting _get_osfhandle.")
		return 0, err
	}

	ret, _, err := syscall.Syscall9(uintptr(proc), 1, uintptr(fd), 0, 0, 0, 0, 0, 0, 0, 0)
	if (err != errSuccess) || (ret == 0) {
		log.WithError(err).Error("error calling api.")
		return 0, err
	}

	return ret, nil
}

func EbpfRingBufferNextRecord(buffer []byte, bufferLength, consumer, producer uint64) *RingBufferRecord {
	if producer <= consumer {
		return nil
	}
	return (*RingBufferRecord)(unsafe.Pointer(&buffer[consumer%bufferLength]))
}

func (reader *WindowsRingBufReader) Init(fd int, ring_buffer_size int) error {
	if fd <= 0 {
		return errors.New("invalid fd provided")
	}
	reader.ringBufferSize = uint64(ring_buffer_size)
	handle, err := EbpfGetHandleFromFd(fd)
	if err != nil {
		return fmt.Errorf("cannot get handle from fd: %w", err)
	}
	var mapHandle windows.Handle
	err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(handle), windows.CurrentProcess(), &mapHandle, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return fmt.Errorf("cannot duplicate handle: %w", err)
	}
	var req operationMapQueryBufferRequest
	req.mapHandle = uint64(handle)
	req.header.id = EBPF_OP_MAP_QUERY_BUF
	req.header.length = uint16(unsafe.Sizeof(req))
	var reply operationMapQueryBufferReply
	err = reader.invokeIoctl(unsafe.Pointer(&req), uint32(unsafe.Sizeof(req)), unsafe.Pointer(&reply), uint32(unsafe.Sizeof(reply)), nil)
	if err != nil {
		return fmt.Errorf("failed to do device io control: %w", err)
	}
	var buffer = uintptr(reply.bufferAddress)
	reader.byteBuf = unsafe.Slice((*byte)(unsafe.Pointer(buffer)), ring_buffer_size)

	reader.currRequest.header.length = uint16(unsafe.Sizeof(reader.currRequest))
	reader.currRequest.header.id = EBPF_OP_MAP_ASYNC_QUERY
	reader.currRequest.mapHandle = uint64(handle)
	reader.currRequest.consumerOffset = reply.consumerOffset

	return nil
}

func (reader *WindowsRingBufReader) fetchNextOffsets() error {
	if reader.consumerOffset > reader.producerOffset {
		return errors.New("offsets are not same, read ahead in buffer")
	}
	var asyncReply operationMapAsyncQueryReply
	var overlapped syscall.Overlapped
	overlapped.HEvent = syscall.Handle(reader.hOverlappedEvent)

	err := reader.invokeIoctl(unsafe.Pointer(&reader.currRequest), uint32(unsafe.Sizeof(reader.currRequest)), unsafe.Pointer(&asyncReply), uint32(unsafe.Sizeof(asyncReply)), unsafe.Pointer(&overlapped))
	if err == error(syscall.Errno(997)) {
		err = nil
	}
	if err != nil {
		log.WithError(err).Error("failed to do async device io control.")
		return err
	}
	waitReason, _, err := WaitForSingleObject.Call(uintptr(overlapped.HEvent), syscall.INFINITE)
	if err != errSuccess {
		return err
	}
	if waitReason != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("failed in wait function: %d", waitReason)

	}
	windows.ResetEvent(windows.Handle(overlapped.HEvent))

	var asyncQueryResult = (*mapAsyncQueryResult)(unsafe.Pointer(&(asyncReply.asyncQueryResult)))
	reader.consumerOffset = asyncQueryResult.consumer
	reader.producerOffset = asyncQueryResult.producer
	return nil
}

func (reader *WindowsRingBufReader) GetNextProcess() (*ProcessInfo, uint32) {
	if reader.consumerOffset == reader.producerOffset {
		err := reader.fetchNextOffsets()
		if err != nil {
			return nil, ERR_RINGBUF_UNKNOWN_ERROR
		}
	}
	record := EbpfRingBufferNextRecord(reader.byteBuf, uint64(reader.ringBufferSize), reader.consumerOffset, reader.producerOffset)
	if record == nil {
		return nil, ERR_RINGBUF_OFFSET_MISMATCH
	}
	if EbpfRingBufferRecordIsLocked(record) {
		return nil, ERR_RINGBUF_TRY_AGAIN
	}
	reader.consumerOffset += uint64(EbpfRingBufferRecordTotalSize(record))
	// This will be communicated in next ioctl
	reader.currRequest.consumerOffset = reader.consumerOffset
	if !EbpfRingBufferRecordIsDiscarded(record) {
		procInfo := (*ProcessInfo)(unsafe.Pointer(&(record.data)))
		return procInfo, ERR_RINGBUF_SUCCESS

	}
	return nil, ERR_RINGBUF_RECORD_DISCARDED
}
