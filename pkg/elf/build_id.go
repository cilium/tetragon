// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
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
	Typ    uint32
}

func parseNote(dat []byte) ([]byte, bool) {
	var note note

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

		if note.Typ == 3 &&
			note.Namesz == 4 &&
			bytes.Equal(name, []byte{'G', 'N', 'U', 0}) &&
			note.Descsz > 0 {
			return desc, true
		}
	}
}

func ParseBuildId(file *os.File) ([]byte, error) {
	f, err := elf.NewFile(file)
	if err != nil {
		return []byte{}, err
	}

	for _, ph := range f.Progs {
		if ph.Type != elf.PT_NOTE {
			continue
		}
		dat := make([]byte, ph.Filesz)
		_, err := io.ReadFull(ph.Open(), dat)
		if err != nil {
			continue
		}
		bid, ok := parseNote(dat)
		if ok {
			return bid, nil
		}
	}
	return []byte{}, nil
}
