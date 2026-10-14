// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const minRingDataSize = 1 << 20

// Data ring header field offsets, mirrors jvmti/proto.h.
const (
	ringOffMagic           = 0
	ringOffVersion         = 4
	ringOffDataSize        = 8
	ringOffProducerPos     = 64
	ringOffConsumerPos     = 128
	ringOffDropped         = 192
	ringOffDroppedDefs     = 200
	ringOffNotify          = 208
	ringOffConsumerWaiting = 212
)

// Ring is the shared memory area passed to a JVMTI agent. The agent is the
// single producer and Tetragon is the single consumer.
type Ring struct {
	fd   int
	data []byte
}

// NewRing creates a memfd-backed ring with a power-of-two data area.
func NewRing(dataSize uint64) (*Ring, error) {
	maxInt := uint64(^uint(0) >> 1)
	if dataSize < minRingDataSize || dataSize&(dataSize-1) != 0 ||
		dataSize > maxInt-uint64(RingHdrSize) {
		return nil, fmt.Errorf("java ring data size must be a power of two >= %d", minRingDataSize)
	}
	fd, err := unix.MemfdCreate("tetragon-java-ring", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("create Java ring memfd: %w", err)
	}
	total := uint64(RingHdrSize) + dataSize
	if err := unix.Ftruncate(fd, int64(total)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("size Java ring: %w", err)
	}
	data, err := unix.Mmap(fd, 0, int(total), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("map Java ring: %w", err)
	}
	binary.LittleEndian.PutUint32(data[ringOffMagic:], RingMagic)
	binary.LittleEndian.PutUint32(data[ringOffVersion:], RingVersion)
	binary.LittleEndian.PutUint64(data[ringOffDataSize:], dataSize)
	return &Ring{fd: fd, data: data}, nil
}

// FD returns the descriptor to pass with SCM_RIGHTS. The receiver gets its
// own descriptor and mapping; callers must keep the ring alive until attach
// and setup have completed.
func (r *Ring) FD() int { return r.fd }

func (r *Ring) Close() error {
	if r == nil {
		return nil
	}
	var errs []error
	if r.data != nil {
		if err := unix.Munmap(r.data); err != nil {
			errs = append(errs, err)
		}
		r.data = nil
	}
	if r.fd >= 0 {
		if err := unix.Close(r.fd); err != nil {
			errs = append(errs, err)
		}
		r.fd = -1
	}
	return errors.Join(errs...)
}

func (r *Ring) Dropped() (entries, definitions uint64) {
	if r == nil || r.data == nil {
		return 0, 0
	}
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.data[ringOffDropped]))),
		atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.data[ringOffDroppedDefs])))
}

// Drain consumes every currently committed record. The callback must not
// retain the record bytes because the producer may immediately reuse them.
func (r *Ring) Drain(callback func(Record) error) error {
	if r == nil || r.data == nil {
		return errors.New("java ring is closed")
	}
	dataSize := binary.LittleEndian.Uint64(r.data[ringOffDataSize:])
	if binary.LittleEndian.Uint32(r.data[ringOffMagic:]) != RingMagic ||
		binary.LittleEndian.Uint32(r.data[ringOffVersion:]) != RingVersion ||
		dataSize == 0 || dataSize&(dataSize-1) != 0 ||
		uint64(len(r.data)) != uint64(RingHdrSize)+dataSize {
		return errors.New("invalid Java ring header")
	}
	producer := (*uint64)(unsafe.Pointer(&r.data[ringOffProducerPos]))
	consumer := (*uint64)(unsafe.Pointer(&r.data[ringOffConsumerPos]))
	mask := dataSize - 1
	for {
		pos := atomic.LoadUint64(consumer)
		end := atomic.LoadUint64(producer)
		if pos == end {
			return nil
		}
		if end-pos > dataSize {
			return errors.New("java ring producer overran consumer")
		}
		offset := uint64(RingHdrSize) + (pos & mask)
		if offset+RecHdrSize > uint64(len(r.data)) {
			return errors.New("java ring record header out of bounds")
		}
		base := r.data[offset:]
		n := binary.LittleEndian.Uint32(base[0:4])
		typ := binary.LittleEndian.Uint32(base[4:8])
		if n == 0 {
			return nil
		} // producer has reserved but not committed
		if n < RecHdrSize || n&(RecAlign-1) != 0 || uint64(n) > dataSize-(pos&mask) {
			return fmt.Errorf("invalid Java ring record size %d", n)
		}
		if typ == RecPad {
			atomic.StoreUint64(consumer, pos+uint64(n))
			continue
		}
		if uint64(n) > uint64(len(base)) {
			return errors.New("java ring record exceeds mapping")
		}
		record := Record{Type: typ, Data: base[RecHdrSize:n]}
		if err := callback(record); err != nil {
			return err
		}
		clear(base[:n])
		atomic.StoreUint64(consumer, pos+uint64(n))
	}
}

type Record struct {
	Type uint32
	Data []byte
}
