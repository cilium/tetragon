// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package javaagent

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestControlMessageAndHookRoundTrip(t *testing.T) {
	want := Hook{
		PolicyID: 7,
		HookID:   2,
		Kind:     HookPrefix,
		Class:    "example/",
		Methods: []HookMethod{
			{Name: "run", Descriptor: "(I)V"},
			{Name: "run", Descriptor: ""},
		},
	}
	payload, err := EncodeHook(want)
	require.NoError(t, err)
	msg, err := (Header{Type: MsgHookAdd, Seq: 19}).Message(payload)
	require.NoError(t, err)
	h, gotPayload, err := ParseMessage(msg)
	require.NoError(t, err)
	require.Equal(t, Header{Type: MsgHookAdd, Seq: 19}, h)
	got, err := DecodeHook(gotPayload)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestDecodeHookRejectsTruncationAndTrailingData(t *testing.T) {
	payload, err := EncodeHook(Hook{PolicyID: 1, HookID: 0, Kind: HookClass, Class: "pkg/Foo"})
	require.NoError(t, err)
	_, err = DecodeHook(payload[:len(payload)-1])
	require.Error(t, err)
	_, err = DecodeHook(append(payload, 1))
	require.Error(t, err)
}

func TestRingDrainAndMethodEventDecode(t *testing.T) {
	ring, err := NewRing(1 << 20)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ring.Close()) })
	data := ring.data[RingHdrSize:]
	// One METHOD_ENTRY record, as emitted by the JVMTI producer.
	binary.LittleEndian.PutUint32(data[0:4], 32)
	binary.LittleEndian.PutUint32(data[4:8], RecMethodEntry)
	binary.LittleEndian.PutUint64(data[8:16], 0x1234)
	binary.LittleEndian.PutUint64(data[16:24], 999)
	binary.LittleEndian.PutUint32(data[24:28], 44)
	binary.LittleEndian.PutUint64(ring.data[ringOffProducerPos:], 32)
	var got Record
	require.NoError(t, ring.Drain(func(record Record) error {
		got = Record{Type: record.Type, Data: append([]byte(nil), record.Data...)}
		return nil
	}))
	require.Equal(t, uint32(RecMethodEntry), got.Type)
	require.Equal(t, uint64(0x1234), binary.LittleEndian.Uint64(got.Data[:8]))
	require.Equal(t, uint64(999), binary.LittleEndian.Uint64(got.Data[8:16]))
	require.Equal(t, uint32(44), binary.LittleEndian.Uint32(got.Data[16:20]))
	require.Equal(t, uint64(32), binary.LittleEndian.Uint64(ring.data[ringOffConsumerPos:]))
}

func TestRingDrainSkipsWrapPadding(t *testing.T) {
	ring, err := NewRing(1 << 20)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ring.Close()) })
	dataSize := uint64(len(ring.data) - RingHdrSize)
	data := ring.data[RingHdrSize:]
	// The producer writes a 16 byte PAD record, then wraps to offset zero.
	pad := data[dataSize-16:]
	binary.LittleEndian.PutUint32(pad[0:4], 16)
	binary.LittleEndian.PutUint32(pad[4:8], RecPad)
	entry := data[:32]
	binary.LittleEndian.PutUint32(entry[0:4], 32)
	binary.LittleEndian.PutUint32(entry[4:8], RecMethodEntry)
	binary.LittleEndian.PutUint64(entry[8:16], 9)
	binary.LittleEndian.PutUint64(ring.data[ringOffConsumerPos:], dataSize-16)
	binary.LittleEndian.PutUint64(ring.data[ringOffProducerPos:], dataSize+32)
	var records int
	require.NoError(t, ring.Drain(func(record Record) error {
		records++
		require.Equal(t, uint32(RecMethodEntry), record.Type)
		return nil
	}))
	require.Equal(t, 1, records)
	require.Equal(t, dataSize+32, binary.LittleEndian.Uint64(ring.data[ringOffConsumerPos:]))
}

func TestRingDrainRejectsOverrun(t *testing.T) {
	ring, err := NewRing(1 << 20)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ring.Close()) })
	binary.LittleEndian.PutUint64(ring.data[ringOffProducerPos:], 1<<20+1)
	require.ErrorContains(t, ring.Drain(func(Record) error { return nil }), "overran")
}

func TestMethodDefinitionAndEntrySubmission(t *testing.T) {
	var got []any
	s := NewServer("/unused", func(
		pid, tid uint32,
		ktime, methodID uint64,
		class, method, desc, policy, message string,
		tags []string,
	) {
		got = append(got, []any{pid, tid, ktime, methodID, class, method, desc, policy, message, tags})
	})
	s.policies[3] = Policy{
		ID:   3,
		Name: "policy",
		Meta: map[uint32]HookMetadata{
			4: {Message: "hit", Tags: []string{"one"}},
		},
	}
	c := &session{server: s, pid: 123, methods: make(map[uint64]methodDefinition)}
	def := make([]byte, 40) // 24 bytes fixed, 9 bytes of strings, and padding.
	binary.LittleEndian.PutUint64(def[0:8], 0x55)
	binary.LittleEndian.PutUint32(def[8:12], 3)
	binary.LittleEndian.PutUint32(def[12:16], 4)
	binary.LittleEndian.PutUint16(def[16:18], 3)
	binary.LittleEndian.PutUint16(def[18:20], 3)
	binary.LittleEndian.PutUint16(def[20:22], 3)
	copy(def[24:], "a/Brun()V")
	require.NoError(t, c.methodDef(def))
	entry := make([]byte, 24)
	binary.LittleEndian.PutUint64(entry[0:8], 0x55)
	binary.LittleEndian.PutUint64(entry[8:16], 1234)
	binary.LittleEndian.PutUint32(entry[16:20], 456)
	require.NoError(t, c.methodEntry(entry))
	require.Len(t, got, 1)
	values := got[0].([]any)
	require.Equal(t, uint32(123), values[0])
	require.Equal(t, uint32(456), values[1])
	require.Equal(t, uint64(1234), values[2])
	require.Equal(t, stableMethodID("a/B", "run", "()V"), values[3])
	require.Equal(t, "a/B", values[4])
	require.Equal(t, "run", values[5])
	require.Equal(t, "()V", values[6])
	require.Equal(t, "policy", values[7])
	require.Equal(t, "hit", values[8])
}
