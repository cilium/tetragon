//go:build windows

package bpf

import (
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

type _ebpf_operation_header struct {
	length uint16
	id     uint32
}

type _ebpf_operation_map_query_buffer_request struct {
	header     _ebpf_operation_header
	map_handle uint64
	index      uint32
}

type _ebpf_operation_map_query_buffer_reply struct {
	header          _ebpf_operation_header
	buffer_address  uint64
	consumer_offset uint64
}

type _ebpf_operation_map_async_query_request struct {
	header          _ebpf_operation_header
	map_handle      uint64
	index           uint32
	consumer_offset uint64
}
type _ebpf_map_async_query_result struct {
	producer   uint64
	consumer   uint64
	lost_count uint64
}

type _ebpf_operation_map_async_query_reply struct {
	header             _ebpf_operation_header
	async_query_result _ebpf_map_async_query_result
}

type ebpf_ring_buffer_record struct {
	length      uint32
	page_offset uint32
	data        [1]uint8
}

type ProcessInfo struct {
	ProcessId         uint32
	ParentProcessId   uint32
	CreatingProcessId uint32
	CreatingThreadId  uint32
	CreationTime      uint64
	ExitTime          uint64
	ProcessExitCode   uint32
	Operation         uint8
}

type GetOsfHandle func(fd int) uint32

var (
	io_pending_err = error(syscall.Errno(windows.ERROR_IO_PENDING))
	success_err    = error(syscall.Errno(windows.ERROR_SUCCESS))
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
	currRequest      _ebpf_operation_map_async_query_request
	producer_offset  uint64
	consumer_offset  uint64
	hSync            uintptr
	hASync           uintptr
	hOverlappedEvent uintptr
	ring_buffer_size uint64
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

func CTL_CODE(DeviceType, Function, Method, Access uint32) uint32 {
	return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
}

func EbpfRingBufferRecordIsLocked(record *ebpf_ring_buffer_record) bool {
	return atomic.LoadUint32(&record.length)&EBPF_RINGBUF_LOCK_BIT != 0
}

func EbpfRingBufferRecordIsDiscarded(record *ebpf_ring_buffer_record) bool {
	return atomic.LoadUint32(&record.length)&EBPF_RINGBUF_DISCARD_BIT != 0
}

func EbpfRingBufferRecordLength(record *ebpf_ring_buffer_record) uint32 {
	return (atomic.LoadUint32(&record.length)) & (uint32(^(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT)))
}

func EbpfRingBufferRecordTotalSize(record *ebpf_ring_buffer_record) uint32 {
	return (EbpfRingBufferRecordLength(record) + uint32(unsafe.Offsetof(record.data)) + 7) & ^uint32(7)
}

func (reader *WindowsRingBufReader) invokeIoctl(request unsafe.Pointer, dwReqSize uint32, response unsafe.Pointer, dwRespSize uint32, overlapped unsafe.Pointer) error {
	var actualReplySize uint32
	var requestSize uint32 = dwReqSize
	var requestPtr unsafe.Pointer = request
	var replySize uint32 = dwRespSize
	var replyPtr unsafe.Pointer = response
	var variableReplySize bool = false
	var err error
	var hDevice uintptr = INVALID_HANDLE_VALUE

	if overlapped == nil {
		if reader.hSync == INVALID_HANDLE_VALUE {
			reader.hSync, _, err = CreateFileW.Call(
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`\\.\EbpfIoDevice`))),
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
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`\\.\EbpfIoDevice`))),
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
		return fmt.Errorf("Erro Opening Device")
	}
	success, _, err := DeviceIoControl.Call(
		uintptr(hDevice),
		uintptr(CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)),
		uintptr(requestPtr),
		uintptr(requestSize),
		uintptr(replyPtr),
		uintptr(replySize),
		uintptr(unsafe.Pointer(&actualReplySize)),
		uintptr(overlapped),
	)
	if (overlapped != nil) && (success == 0) && (err == io_pending_err) {
		success = 1
		err = nil
	}

	if success == 0 {
		fmt.Printf("Device io control failed. Error = %d\n", syscall.GetLastError())
		return err
	}

	if actualReplySize != replySize && !variableReplySize {
		fmt.Printf("\nDevice io control incorrect reply. ")
		return err
	}
	return nil

}
func CreateOverlappedEvent() (uintptr, error) {
	var err error
	var hEvent uintptr
	hEvent, _, err = CreateEventW.Call(0, 0, 0, 0)
	if err != error(syscall.Errno(0)) {
		fmt.Printf("Error = %s", err.Error())
		return INVALID_HANDLE_VALUE, err
	}
	ResetEvent.Call(hEvent)
	return hEvent, nil
}

func EbpfGetHandleFromFd(fd int) (uintptr, error) {
	var moduleHandle uintptr

	moduleHandle, _, err := GetModuleHandleW.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`ucrtbased.dll`))))
	if (err != success_err) || (moduleHandle == 0) {
		moduleHandle, _, err = GetModuleHandleW.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`ucrtbase.dll`))))
	}
	if (err != success_err) || (moduleHandle == 0) {
		fmt.Printf("Error getting ucrt base. Wont work")
		return 0, err
	}
	proc, err := syscall.GetProcAddress(syscall.Handle(moduleHandle), "_get_osfhandle")
	if (err != nil) || (proc == 0) {
		fmt.Printf("Error getting _get_osfhandle. Won't work")
		return 0, err
	}

	ret, _, err := syscall.Syscall9(uintptr(proc), 1, uintptr(fd), 0, 0, 0, 0, 0, 0, 0, 0)
	if (err != success_err) || (ret == 0) {
		fmt.Printf("Error calling api.  Won't work")
		return 0, err
	}

	return ret, nil
}

func EbpfRingBufferNextRecord(buffer []byte, bufferLength, consumer, producer uint64) *ebpf_ring_buffer_record {
	if producer <= consumer {
		return nil
	}
	return (*ebpf_ring_buffer_record)(unsafe.Pointer(&buffer[consumer%bufferLength]))
}

func (reader *WindowsRingBufReader) Init(fd int, ring_buffer_size int) error {
	if fd <= 0 {
		return fmt.Errorf("Invalid FD provided")
	}
	reader.ring_buffer_size = uint64(ring_buffer_size)
	handle, err := EbpfGetHandleFromFd(fd)
	if err != nil {
		return fmt.Errorf("Cannot get handle from FD")
	}
	var map_handle windows.Handle
	err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(handle), windows.CurrentProcess(), &map_handle, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return fmt.Errorf("Cannot duplicate handle")
	}
	var req _ebpf_operation_map_query_buffer_request
	req.map_handle = uint64(handle)
	req.header.id = EBPF_OP_MAP_QUERY_BUF
	req.header.length = uint16(unsafe.Sizeof(req))
	var reply _ebpf_operation_map_query_buffer_reply
	err = reader.invokeIoctl(unsafe.Pointer(&req), uint32(unsafe.Sizeof(req)), unsafe.Pointer(&reply), uint32(unsafe.Sizeof(reply)), nil)
	if err != nil {
		return fmt.Errorf("Failed to do device io control")
	}
	var buffer uintptr
	buffer = uintptr(reply.buffer_address)
	reader.byteBuf = unsafe.Slice((*byte)(unsafe.Pointer(buffer)), ring_buffer_size)

	reader.currRequest.header.length = uint16(unsafe.Sizeof(reader.currRequest))
	reader.currRequest.header.id = EBPF_OP_MAP_ASYNC_QUERY
	reader.currRequest.map_handle = uint64(handle)
	reader.currRequest.consumer_offset = reply.consumer_offset

	return nil
}

func (reader *WindowsRingBufReader) fetchNextOffsets() error {
	if reader.consumer_offset > reader.producer_offset {
		return fmt.Errorf("Offsets are not same, read ahead in Buffer")
	}
	var async_reply _ebpf_operation_map_async_query_reply
	var overlapped syscall.Overlapped
	overlapped.HEvent = syscall.Handle(reader.hOverlappedEvent)

	err := reader.invokeIoctl(unsafe.Pointer(&reader.currRequest), uint32(unsafe.Sizeof(reader.currRequest)), unsafe.Pointer(&async_reply), uint32(unsafe.Sizeof(async_reply)), unsafe.Pointer(&overlapped))
	if err == error(syscall.Errno(997)) {
		err = nil
	}
	if err != nil {
		fmt.Printf(err.Error())
		return fmt.Errorf("Failed to do async device io control")
	}
	waitReason, _, err := WaitForSingleObject.Call(uintptr(overlapped.HEvent), syscall.INFINITE)
	if err != success_err {
		return err
	}
	if waitReason != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("Failed in wait function")

	}
	windows.ResetEvent(windows.Handle(overlapped.HEvent))

	var async_query_result *_ebpf_map_async_query_result = (*_ebpf_map_async_query_result)(unsafe.Pointer(&(async_reply.async_query_result)))
	reader.consumer_offset = async_query_result.consumer
	reader.producer_offset = async_query_result.producer
	return nil
}

func (reader *WindowsRingBufReader) GetNextProcess() (*ProcessInfo, uint32) {
	if reader.consumer_offset == reader.producer_offset {
		err := reader.fetchNextOffsets()
		if err != nil {
			return nil, ERR_RINGBUF_UNKNOWN_ERROR
		}
	}
	record := EbpfRingBufferNextRecord(reader.byteBuf, uint64(reader.ring_buffer_size), reader.consumer_offset, reader.producer_offset)
	if record == nil {
		return nil, ERR_RINGBUF_OFFSET_MISMATCH
	}
	if EbpfRingBufferRecordIsLocked(record) {
		return nil, ERR_RINGBUF_TRY_AGAIN
	}
	reader.consumer_offset += uint64(EbpfRingBufferRecordTotalSize(record))
	// This will be communicated in next ioctl
	reader.currRequest.consumer_offset = reader.consumer_offset
	if !EbpfRingBufferRecordIsDiscarded(record) {
		procInfo := (*ProcessInfo)(unsafe.Pointer(&(record.data)))
		return procInfo, ERR_RINGBUF_SUCCESS

	}
	return nil, ERR_RINGBUF_RECORD_DISCARDED
}
