package tracing

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/observer"
	"golang.org/x/sys/unix"
)

type perfEventMmap2 struct {
	Pid         uint32
	Tid         uint32
	Start       uint64
	Len         uint64
	Pgoff       uint64
	BuildIdSize uint8
	Reserved1   uint8
	Reserved2   uint16
	BuildId     [20]uint8
	Prot        uint32
	Flags       uint32
}

var perfEventHeaderSize = binary.Size(bpf.PerfEventHeader{})

func readProcessBinary(header *bpf.PerfEventHeader, rd *bytes.Reader) (*tracing.MsgProcessLoaderUnix, error) {
	var mmap2 perfEventMmap2
	var time uint64

	if err := binary.Read(rd, binary.LittleEndian, &mmap2); err != nil {
		return nil, err
	}

	pathSz := (int(header.TotalSize) - int(binary.Size(time))) - (binary.Size(perfEventMmap2{}) + perfEventHeaderSize)
	path := make([]byte, pathSz)

	if _, err := io.ReadFull(rd, path); err != nil {
		return nil, err
	}
	path = bytes.Trim(path, "\x00")

	if err := binary.Read(rd, binary.LittleEndian, &time); err != nil {
		return nil, err
	}

	return &tracing.MsgProcessLoaderUnix{
		Pid:     mmap2.Pid,
		Tid:     mmap2.Tid,
		Ktime:   time,
		Path:    string(path),
		Buildid: mmap2.BuildId[:],
	}, nil
}

func handleMmap2(header *bpf.PerfEventHeader, rd *bytes.Reader, cpu int) ([]observer.Event, error) {
	msg, err := readProcessBinary(header, rd)
	if err != nil {
		return nil, err
	}
	return []observer.Event{msg}, nil
}

func init() {
	observer.RegisterPerfEventHandler(unix.PERF_RECORD_MMAP2, handleMmap2)
}
