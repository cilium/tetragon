// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
)

// Integer represents all possible integer types.
// Remove when x/exp/constraints is moved to the standard library.
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// align returns 'n' updated to 'alignment' boundary.
func align[I Integer](n, alignment I) I {
	return (n + alignment - 1) / alignment * alignment
}

type note struct {
	Namesz uint32
	Descsz uint32
	Type   uint32
}

// ParseBuildIdFromNotes returns the GNU build ID found in a raw ELF notes blob,
// decoded with the given byte order. Callers holding notes without an ELF
// container around them, such as the running kernel's /sys/kernel/notes, can use
// this directly; ParseBuildId wraps it for a parsed ELF file.
func ParseBuildIdFromNotes(dat []byte, order binary.ByteOrder) ([]byte, bool) {
	var note note

	dr := bytes.NewReader(dat)

	for {
		if err := binary.Read(dr, order, &note); err != nil {
			return []byte{}, false
		}

		name := make([]byte, align(note.Namesz, 4))
		if err := binary.Read(dr, order, name); err != nil {
			return []byte{}, false
		}

		desc := make([]byte, align(note.Descsz, 4))
		if err := binary.Read(dr, order, desc); err != nil {
			return []byte{}, false
		}

		if note.Type == 3 && // NT_GNU_BUILD_ID = 3
			note.Namesz == 4 &&
			bytes.Equal(name, []byte{'G', 'N', 'U', 0}) &&
			note.Descsz > 0 {
			return desc, true
		}
	}
}

// maxNoteSize bounds a PT_NOTE segment we will read: notes are small (a
// build-id note is ~36 bytes), so an implausibly large Filesz is a crafted or
// corrupt ELF. A resolvePathInContainer build-id target is container-supplied,
// so bound the allocation rather than trust the header.
const maxNoteSize = 1 << 20 // 1 MiB

func (se *SafeELFFile) ParseBuildID() ([]byte, error) {
	for _, ph := range se.Progs {
		if ph.Type != elf.PT_NOTE {
			continue
		}
		if ph.Filesz > maxNoteSize {
			continue
		}
		dat := make([]byte, ph.Filesz)
		if _, err := io.ReadFull(ph.Open(), dat); err != nil {
			continue
		}

		if bid, ok := ParseBuildIdFromNotes(dat, se.ByteOrder); ok {
			return bid, nil
		}
	}
	return []byte{}, errors.New("failed to find build ID note")
}
