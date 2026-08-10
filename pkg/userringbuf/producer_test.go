// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package userringbuf

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlign8(t *testing.T) {
	for input, expected := range map[int]int{0: 0, 1: 8, 8: 8, 9: 16, 416: 416} {
		require.Equal(t, expected, align8(input))
	}
}

func memoryProducer(size int) (*Producer, *uint64, *uint64) {
	consumer := new(uint64)
	producer := new(uint64)
	return &Producer{
		consumerPos: consumer,
		producerPos: producer,
		data:        make([]byte, 2*size),
		mask:        uint64(size - 1),
		size:        uint64(size),
	}, consumer, producer
}

func TestSubmitFullDoesNotAdvanceProducer(t *testing.T) {
	p, _, producer := memoryProducer(64)
	require.NoError(t, p.Submit(make([]byte, 56)))
	require.Equal(t, uint64(64), *producer)
	before := append([]byte{}, p.data...)
	require.ErrorIs(t, p.Submit([]byte("x")), ErrFull)
	require.Equal(t, uint64(64), *producer)
	require.Equal(t, before, p.data)
}

func TestConcurrentSubmitProducesIntactRecords(t *testing.T) {
	const records = 100
	p, _, producer := memoryProducer(4096)
	var wg sync.WaitGroup
	for value := range records {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := make([]byte, 8)
			binary.LittleEndian.PutUint64(payload, uint64(value))
			require.NoError(t, p.Submit(payload))
		}()
	}
	wg.Wait()
	require.Equal(t, uint64(records*16), *producer)

	seen := make(map[uint64]bool, records)
	for offset := 0; offset < records*16; offset += 16 {
		require.Equal(t, uint32(8), binary.LittleEndian.Uint32(p.data[offset:offset+4]))
		seen[binary.LittleEndian.Uint64(p.data[offset+8:offset+16])] = true
	}
	for value := range records {
		require.True(t, seen[uint64(value)])
	}
}
