// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

// Package userringbuf provides a non-blocking userspace producer used by the
// Java bridge integration test and as a reference for the Java FFM producer.
package userringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var ErrFull = errors.New("user ring buffer full")

const (
	busyBit   = uint32(1 << 31)
	headerLen = 8
)

type Producer struct {
	consumerMapping []byte
	producerMapping []byte
	consumerPos     *uint64
	producerPos     *uint64
	data            []byte
	mask            uint64
	size            uint64
	mu              sync.Mutex
}

func NewProducer(m *ebpf.Map) (*Producer, error) {
	if m.Type() != ebpf.UserRingbuf {
		return nil, fmt.Errorf("map type %s is not BPF_MAP_TYPE_USER_RINGBUF", m.Type())
	}
	size := int(m.MaxEntries())
	if size == 0 || size&(size-1) != 0 {
		return nil, fmt.Errorf("map size %d is not a power of two", size)
	}
	pageSize := os.Getpagesize()
	consumer, err := unix.Mmap(m.FD(), 0, pageSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap consumer page: %w", err)
	}
	producer, err := unix.Mmap(m.FD(), int64(pageSize), pageSize+2*size,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(consumer)
		return nil, fmt.Errorf("mmap producer pages: %w", err)
	}
	return &Producer{
		consumerMapping: consumer,
		producerMapping: producer,
		consumerPos:     (*uint64)(unsafe.Pointer(&consumer[0])),
		producerPos:     (*uint64)(unsafe.Pointer(&producer[0])),
		data:            producer[pageSize:],
		mask:            uint64(size - 1),
		size:            uint64(size),
	}, nil
}

func align8(value int) int { return (value + 7) &^ 7 }

func (p *Producer) Submit(payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	total := uint64(headerLen + align8(len(payload)))
	if total > p.size {
		return fmt.Errorf("payload of %d bytes exceeds ring size %d", len(payload), p.size)
	}
	producer := atomic.LoadUint64(p.producerPos)
	consumer := atomic.LoadUint64(p.consumerPos)
	if producer-consumer+total > p.size {
		return ErrFull
	}

	offset := producer & p.mask
	length := (*uint32)(unsafe.Pointer(&p.data[offset]))
	padding := (*uint32)(unsafe.Pointer(&p.data[offset+4]))
	atomic.StoreUint32(length, uint32(len(payload))|busyBit)
	atomic.StoreUint32(padding, 0)
	record := p.data[offset+headerLen : offset+total]
	clear(record)
	copy(record, payload)
	atomic.StoreUint32(length, uint32(len(payload)))
	atomic.StoreUint64(p.producerPos, producer+total)
	return nil
}

func (p *Producer) Close() error {
	producerErr := unix.Munmap(p.producerMapping)
	consumerErr := unix.Munmap(p.consumerMapping)
	return errors.Join(producerErr, consumerErr)
}
