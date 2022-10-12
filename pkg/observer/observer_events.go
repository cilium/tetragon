package observer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"golang.org/x/sys/unix"
)

var perfEventHeaderSize = binary.Size(bpf.PerfEventHeader{})

type perfEventSample struct {
	Size uint32
}

type perfEventLost struct {
	ID   uint64
	Lost uint64
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

func (k *Observer) receiveRawEvent(data []byte, cpu int) error {
	rd := bytes.NewReader(data)

	var header bpf.PerfEventHeader
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
	}

	return nil
}
