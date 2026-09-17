// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

// Package javaipc implements the shared-memory ring used to receive
// method-entry records from the Java monitoring agent. Tetragon creates and
// owns the ring file at a well-known path; the agent just opens the
// existing file and writes records into it. There is no handshake and no
// authentication of the writer, so this is meant for local/trusted use.
package javaipc

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/javaapi"
	"golang.org/x/sys/unix"
)

const (
	ringMagic       = uint32(0x4a52534a) // "JRSJ" in little endian
	ringVersion     = uint32(1)
	ringHeaderSize  = 256
	ringProducerOff = 64
	ringConsumerOff = 128
	ringNotifyOff   = 192
)

const (
	// These are the public ABI values used by the Java FFM producer.
	RecordSize      = 432
	DefaultRingSize = 4 << 20
)

// Ring is a shared-memory SPSC ring mapped from a file: the Java agent is
// the sole producer, Tetragon is the sole consumer.
type Ring struct {
	path     string
	data     []byte
	producer *uint64
	consumer *uint64
	notify   *uint32
	slots    uint64
	mask     uint64
}

// ringGeometry returns the slot count and total mapped length for a ring
// that fits within DefaultRingSize. The Java agent computes the same values
// independently from the same RecordSize/ringHeaderSize/DefaultRingSize
// constants, so the two sides agree on ring layout without negotiating it.
func ringGeometry() (slots uint64, mappedLength uint64) {
	slots = 1
	for ringHeaderSize+(slots<<1)*RecordSize <= DefaultRingSize {
		slots <<= 1
	}
	slots >>= 1
	return slots, uint64(ringHeaderSize) + slots*RecordSize
}

// CreateRing creates (truncating any existing file) and mmaps the ring file
// at path, writing a fresh header. Tetragon calls this once at startup.
func CreateRing(path string) (*Ring, error) {
	if path == "" {
		return nil, nil
	}
	slots, mappedLength := ringGeometry()
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, 0o666)
	if err != nil {
		return nil, fmt.Errorf("create Java ring %q: %w", path, err)
	}
	defer unix.Close(fd)
	// Tetragon usually runs as root while the JVM doesn't; open()'s mode is
	// subject to the umask, so force it explicitly rather than relying on
	// the umask leaving the world-writable bit intact.
	if err := unix.Fchmod(fd, 0o666); err != nil {
		return nil, fmt.Errorf("chmod Java ring %q: %w", path, err)
	}
	if err := unix.Ftruncate(fd, int64(mappedLength)); err != nil {
		return nil, fmt.Errorf("size Java ring %q: %w", path, err)
	}
	header := make([]byte, ringHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], ringMagic)
	binary.LittleEndian.PutUint32(header[4:8], ringVersion)
	binary.LittleEndian.PutUint32(header[8:12], RecordSize)
	binary.LittleEndian.PutUint64(header[16:24], slots)
	if _, err := unix.Pwrite(fd, header, 0); err != nil {
		return nil, fmt.Errorf("write Java ring header %q: %w", path, err)
	}
	return openRing(path)
}

// openRing opens and mmaps an existing, already-populated ring file,
// validating its header. Used by CreateRing right after writing the header,
// and directly by tests.
func openRing(path string) (*Ring, error) {
	clean := filepath.Clean(path)
	if clean != path || !filepath.IsAbs(path) || strings.Contains(path, "\x00") {
		return nil, fmt.Errorf("invalid Java ring path %q", path)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open Java ring %q: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err != nil {
		return nil, fmt.Errorf("stat Java ring %q: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < ringHeaderSize {
		return nil, fmt.Errorf("invalid Java ring file %q", path)
	}
	mapped, err := unix.Mmap(fd, 0, int(st.Size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map Java ring %q: %w", path, err)
	}
	bad := func(err error) (*Ring, error) {
		_ = unix.Munmap(mapped)
		return nil, err
	}
	if binary.LittleEndian.Uint32(mapped[0:4]) != ringMagic ||
		binary.LittleEndian.Uint32(mapped[4:8]) != ringVersion ||
		binary.LittleEndian.Uint32(mapped[8:12]) != RecordSize {
		return bad(fmt.Errorf("invalid Java ring header in %q", path))
	}
	slots := binary.LittleEndian.Uint64(mapped[16:24])
	if slots < 2 || slots&(slots-1) != 0 ||
		slots > (uint64(st.Size)-uint64(ringHeaderSize))/RecordSize {
		return bad(fmt.Errorf("invalid Java ring slot count %d", slots))
	}
	return &Ring{
		path:     path,
		data:     mapped,
		producer: (*uint64)(unsafe.Pointer(&mapped[ringProducerOff])),
		consumer: (*uint64)(unsafe.Pointer(&mapped[ringConsumerOff])),
		notify:   (*uint32)(unsafe.Pointer(&mapped[ringNotifyOff])),
		slots:    slots,
		mask:     slots - 1,
	}, nil
}

// Close unmaps the ring and removes the backing file.
func (r *Ring) Close() error {
	if r == nil || r.data == nil {
		return nil
	}
	err := unix.Munmap(r.data)
	r.data = nil
	if r.path != "" {
		_ = os.Remove(r.path)
	}
	return err
}

// Serve drains records as they arrive, validating each one and invoking
// callback for it, until ctx is cancelled.
func (r *Ring) Serve(ctx context.Context, callback func([]byte)) {
	for {
		if r.drain(func(data []byte) {
			if err := javaapi.PreparePacket(data); err == nil {
				callback(data)
			}
		}) != 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !waitForRing(r, ctx.Done()) {
			return
		}
	}
}

func (r *Ring) drain(callback func([]byte)) int {
	count := 0
	for {
		consumer := atomic.LoadUint64(r.consumer)
		producer := atomic.LoadUint64(r.producer)
		if consumer == producer {
			return count
		}
		offset := uint64(ringHeaderSize) + (consumer&r.mask)*RecordSize
		// The callback must consume the record synchronously. The observer
		// copies it into its queue before this release allows the producer to
		// reuse the slot, avoiding an extra allocation and copy here.
		callback(r.data[offset : offset+RecordSize])
		atomic.StoreUint64(r.consumer, consumer+1)
		count++
	}
}

func waitForRing(r *Ring, ctxDone <-chan struct{}) bool {
	for {
		producer := atomic.LoadUint64(r.producer)
		consumer := atomic.LoadUint64(r.consumer)
		if producer != consumer {
			return true
		}
		seq := atomic.LoadUint32(r.notify)
		if atomic.LoadUint64(r.producer) != consumer {
			return true
		}
		// A bounded wait makes cancellation observable even if the producer
		// exits without waking the futex.
		timeout := unix.NsecToTimespec(int64(100 * time.Millisecond))
		_, _, errno := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(r.notify)), 0, uintptr(seq), uintptr(unsafe.Pointer(&timeout)), 0, 0)
		if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR && errno != unix.ETIMEDOUT {
			return false
		}
		select {
		case <-ctxDone:
			return false
		default:
		}
	}
}
