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

func parseNote(dat []byte) ([]byte, bool) {
	var note note

	const NT_GNU_BUILD_ID = 3
	dr := bytes.NewReader(dat)

	for {
		if err := binary.Read(dr, binary.LittleEndian, &note); err != nil {
			return []byte{}, false
		}

		name := make([]byte, align(note.Namesz, 4))
		if err := binary.Read(dr, binary.LittleEndian, name); err != nil {
			return []byte{}, false
		}

		desc := make([]byte, align(note.Descsz, 4))
		if err := binary.Read(dr, binary.LittleEndian, desc); err != nil {
			return []byte{}, false
		}

		if note.Type == NT_GNU_BUILD_ID &&
			note.Namesz == 4 &&
			bytes.Equal(name, []byte{'G', 'N', 'U', 0}) &&
			note.Descsz > 0 {
			return desc, true
		}
	}
}

func (se *SafeELFFile) ParseBuildID() ([]byte, error) {
	for _, ph := range se.Progs {
		if ph.Type != elf.PT_NOTE {
			continue
		}
		dat := make([]byte, ph.Filesz)
		if _, err := io.ReadFull(ph.Open(), dat); err != nil {
			continue
		}
		if bid, ok := parseNote(dat); ok {
			return bid, nil
		}
	}
	return []byte{}, errors.New("failed to find build ID note")
}
