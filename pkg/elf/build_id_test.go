// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// noteBlob builds a raw ELF notes blob with the given header fields, name and
// description, as ParseBuildIdFromNotes expects to find them.
func noteBlob(t *testing.T, namesz, descsz uint32, name, desc []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, note{
		Namesz: namesz,
		Descsz: descsz,
		Type:   3, // NT_GNU_BUILD_ID
	}))
	buf.Write(name)
	buf.Write(desc)
	return buf.Bytes()
}

func TestParseBuildIdFromNotes(t *testing.T) {
	desc := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	blob := noteBlob(t, 4, uint32(len(desc)), []byte("GNU\x00"), desc)

	got, ok := ParseBuildIdFromNotes(blob, binary.LittleEndian)
	require.True(t, ok)
	require.Equal(t, desc, got)
}

// TestParseBuildIdFromNotesRejectsOversizedFields checks that the sizes
// declared by a note are bounded by the bytes actually present. A
// resolvePathInContainer target is container-supplied, so a note claiming
// ~4 GiB name and description fields must not be allocated before the read
// fails.
func TestParseBuildIdFromNotesRejectsOversizedFields(t *testing.T) {
	blob := noteBlob(t, 0xFFFFFFFC, 0xFFFFFFFC, nil, nil)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, ok := ParseBuildIdFromNotes(blob, binary.LittleEndian)
	runtime.ReadMemStats(&after)

	require.False(t, ok)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20),
		"oversized note fields must be rejected before they are allocated")
}

// TestParseBuildIdFromNotesRejectsWrappingSize covers a size whose 4-byte
// alignment wraps in 32-bit arithmetic: it must be rejected, not silently
// treated as a zero-length field.
func TestParseBuildIdFromNotesRejectsWrappingSize(t *testing.T) {
	blob := noteBlob(t, 0xFFFFFFFE, 0, nil, nil)

	_, ok := ParseBuildIdFromNotes(blob, binary.LittleEndian)
	require.False(t, ok)
}
