// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/unix"
)

type usdtAddrs struct {
	Off  uint64
	Base uint64
	Sema uint64
}

type elfNoteHeader struct {
	NameSize int32
	DescSize int32
	Type     int32
}

func getBase(se *SafeELFFile) (uint64, error) {
	sections := se.SectionsByName(".stapsdt.base")
	if len(sections) > 1 {
		return 0, errors.New("more than 1 .stapsdt.base sections")
	}
	if len(sections) == 1 {
		return sections[0].Addr, nil
	}
	return 0, nil
}

// Integer represents all possible integer types.
// Remove when x/exp/constraints is moved to the standard library.
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// align returns 'n' updated to 'alignment' boundary.
func align[I Integer](n, alignment I) I {
	return (n + alignment - 1) / alignment * alignment
}

func (se *SafeELFFile) UsdtTargets() ([]*UsdtTarget, error) {
	var targets []*UsdtTarget

	base, err := getBase(se)
	if err != nil {
		return nil, err
	}

	sections := se.SectionsByType(elf.SHT_NOTE)
	if len(sections) == 0 {
		return nil, errors.New("no note section found in vDSO ELF")
	}

	for _, sec := range sections {
		sr := sec.Open()
		var n elfNoteHeader

		// Read notes until we find one named 'stapsdt'.
		for {
			if err := binary.Read(sr, se.ByteOrder, &n); err != nil {
				if errors.Is(err, io.EOF) {
					// We looked at all the notes in this section
					break
				}
				return nil, fmt.Errorf("reading note header: %w", err)
			}

			// If a note name is defined, it follows the note header.
			var note string

			if n.NameSize > 0 {
				// Read the note name, aligned to 4 bytes.
				buf := make([]byte, align(n.NameSize, 4))
				if err := binary.Read(sr, se.ByteOrder, &buf); err != nil {
					return nil, fmt.Errorf("reading note name: %w", err)
				}

				// Read nul-terminated string.
				note = unix.ByteSliceToString(buf[:n.NameSize])
			}

			if note != "stapsdt" || n.Type != 3 {
				// Discard the note descriptor if it exists but we're not interested in it.
				if _, err := io.CopyN(io.Discard, sr, int64(align(n.DescSize, 4))); err != nil {
					return nil, err
				}
				continue
			}

			var (
				spec  UsdtSpec
				addrs usdtAddrs
			)

			if n.DescSize < int32(unsafe.Sizeof(addrs))+3 {
				return nil, errors.New("failed to read elf note")
			}

			if err := binary.Read(sr, se.ByteOrder, &addrs); err != nil {
				return nil, fmt.Errorf("reading note descriptor: %w", err)
			}

			size := align(n.DescSize, 4)
			data := make([]byte, size-int32(unsafe.Sizeof(addrs)))
			if err := binary.Read(sr, se.ByteOrder, &data); err != nil {
				return nil, fmt.Errorf("reading note descriptor: %w", err)
			}

			parseStr := func(arr []byte) (string, []byte, error) {
				idx := bytes.IndexByte(arr, 0)
				if idx == -1 {
					return "", nil, errors.New("failed to parse usdt string")
				}
				return string(arr[:idx]), arr[idx+1:], nil
			}

			spec.Provider, data, err = parseStr(data)
			if err != nil {
				return nil, err
			}
			spec.Name, data, err = parseStr(data)
			if err != nil {
				return nil, err
			}
			spec.ArgsStr, _, err = parseStr(data)
			if err != nil {
				return nil, err
			}
			spec.Off = addrs.Off
			spec.Base = addrs.Base
			spec.Sema = addrs.Sema

			ipAbs := spec.Off
			if base != 0 && spec.Base != 0 {
				ipAbs += base - spec.Base
			}

			prog := se.ProgByVaddr(ipAbs)
			if prog == nil {
				return nil, fmt.Errorf("failed to find elf program header for %x", ipAbs)
			}

			if prog.Flags&elf.PF_X == 0 {
				return nil, fmt.Errorf("failed to find elf program header for %x with PF_X", ipAbs)
			}

			ipRel := ipAbs - prog.Vaddr + prog.Off

			var semaOff uint64

			if spec.Sema != 0 {
				prog := se.ProgByVaddr(spec.Sema)
				if prog == nil {
					return nil, fmt.Errorf("failed to find elf program header for %x", spec.Sema)
				}

				if prog.Flags&elf.PF_X != 0 {
					return nil, fmt.Errorf("failed to find elf program header for %x without PF_X", spec.Sema)
				}

				semaOff = spec.Sema - prog.Vaddr + prog.Off
			}

			parseArgs(&spec)

			target := &UsdtTarget{
				Spec:    &spec,
				IpAbs:   ipAbs,
				IpRel:   ipRel,
				SemaOff: semaOff,
			}

			targets = append(targets, target)
		}
	}

	return targets, nil
}
