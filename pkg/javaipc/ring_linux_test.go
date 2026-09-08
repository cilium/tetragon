// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/api/javaapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

func TestRingDrainAndValidation(t *testing.T) {
	path := t.TempDir() + "/ring"
	slots := uint64(2)
	data := make([]byte, ringHeaderSize+int(slots)*RecordSize)
	binary.LittleEndian.PutUint32(data[0:4], ringMagic)
	binary.LittleEndian.PutUint32(data[4:8], ringVersion)
	binary.LittleEndian.PutUint32(data[8:12], RecordSize)
	binary.LittleEndian.PutUint64(data[16:24], slots)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ring, err := openRing(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	copy(ring.data[ringHeaderSize:ringHeaderSize+RecordSize], []byte{29})
	atomic.StoreUint64(ring.producer, 1)
	var got []byte
	if n := ring.drain(func(record []byte) { got = record }); n != 1 {
		t.Fatalf("drained %d records, want 1", n)
	}
	if len(got) != RecordSize || got[0] != 29 {
		t.Fatalf("unexpected record: len=%d opcode=%d", len(got), got[0])
	}
	if consumer := atomic.LoadUint64(ring.consumer); consumer != 1 {
		t.Fatalf("consumer index %d, want 1", consumer)
	}
}

func TestCreateRingAndServe(t *testing.T) {
	path := t.TempDir() + "/java.ring"
	ring, err := CreateRing(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("ring file not created: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	received := make(chan []byte, 1)
	done := make(chan struct{})
	go func() {
		ring.Serve(ctx, func(data []byte) {
			cp := append([]byte(nil), data...)
			received <- cp
		})
		close(done)
	}()

	record := encodeJavaRecord(t, 1)
	copy(ring.data[ringHeaderSize:ringHeaderSize+RecordSize], record)
	atomic.StoreUint64(ring.producer, 1)

	select {
	case got := <-received:
		if pid := binary.LittleEndian.Uint32(got[16:20]); pid != 1 {
			t.Fatalf("record PID %d, want 1", pid)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ring record")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ring file still exists after Close: %v", err)
	}
}

func encodeJavaRecord(t *testing.T, pid uint32) []byte {
	t.Helper()
	msg := javaapi.MsgJava{
		Common:     processapi.MsgCommon{Op: ops.MSG_OP_JAVA, Size: javaapi.MsgJavaSize, Ktime: 1},
		ProcessKey: processapi.MsgExecveKey{Pid: pid},
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, &msg); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}
