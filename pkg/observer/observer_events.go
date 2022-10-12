package observer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/cilium/tetragon/pkg/reader/buildid"
	"golang.org/x/sys/unix"
)

var perfEventHeaderSize = binary.Size(perfEventHeader{})

type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

type perfEventSample struct {
	Size uint32
}

type perfEventLost struct {
	ID   uint64
	Lost uint64
}

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

func readLostRecords(rd io.Reader) (uint64, error) {
	lost := perfEventLost{}
	if err := binary.Read(rd, binary.LittleEndian, &lost); err != nil {
		return 0, fmt.Errorf("can't read lost records header: %v", err)
	}
	return lost.Lost, nil
}

func readRawSample(rd io.Reader) ([]byte, error) {
	sample := perfEventSample{}
	if err := binary.Read(rd, binary.LittleEndian, &sample); err != nil {
		return nil, fmt.Errorf("read sample size: %v", err)
	}

	data := make([]byte, sample.Size)
	if _, err := io.ReadFull(rd, data); err != nil {
		return nil, fmt.Errorf("read sample: %v", err)
	}
	return data, nil
}

func readMmap2Event(rd *bytes.Reader, cpu int, header perfEventHeader) (string, []byte, error) {
	var mmap2 perfEventMmap2

	if err := binary.Read(rd, binary.LittleEndian, &mmap2); err != nil {
		return "", []byte{}, err
	}

	if mmap2.BuildIdSize == 0 {
		return "", []byte{}, nil
	}

	pathSz := int(header.Size) - (binary.Size(perfEventMmap2{}) + perfEventHeaderSize)
	path := make([]byte, pathSz)
	if _, err := io.ReadFull(rd, path); err != nil {
		return "", []byte{}, err
	}
	path = bytes.Trim(path, "\x00")

	return string(path), mmap2.BuildId[:], nil
}

func (k *Observer) receiveRawEvent(data []byte, cpu int) error {
	rd := bytes.NewReader(data)

	var header perfEventHeader
	if err := binary.Read(rd, binary.LittleEndian, &header); err != nil {
		return err
	}

	switch header.Type {
	case unix.PERF_RECORD_LOST:
		lost, err := readLostRecords(rd)
		if err != nil {
			return err
		}
		k.lostCntr += int(lost)
		ringbufmetrics.LostSet(float64(k.lostCntr))

	case unix.PERF_RECORD_SAMPLE:
		sample, err := readRawSample(rd)
		if err != nil {
			return err
		}
		k.receiveEvent(sample, cpu)
		ringbufmetrics.ReceivedSet(float64(k.recvCntr))

	case unix.PERF_RECORD_MMAP2:
		path, id, err := readMmap2Event(rd, cpu, header)
		if err != nil {
			return err
		}
		if path != "" {
			buildid.Set(path, id)
		}

	case unix.PERF_RECORD_EXIT:
	case unix.PERF_RECORD_FORK:
		// mmap2 enables exit/fork events, ignore them for now

	default:
		k.unknownCntr++
		ringbufmetrics.UnknownSet(float64(k.unknownCntr))
	}

	return nil
}
