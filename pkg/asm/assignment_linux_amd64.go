// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package asm

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	ASM_ASSIGNMENT_TYPE_NONE      uint8 = 0
	ASM_ASSIGNMENT_TYPE_CONST     uint8 = 1
	ASM_ASSIGNMENT_TYPE_REG       uint8 = 2
	ASM_ASSIGNMENT_TYPE_REG_OFF   uint8 = 3
	ASM_ASSIGNMENT_TYPE_REG_DEREF uint8 = 4
)

var errNext = errors.New("next")

type Assignment struct {
	Type    uint8
	Pad     uint8
	Src     uint16
	Dst     uint16
	SrcSize uint8
	DstSize uint8
	Off     uint64
}

type fn func(str string, ass *Assignment) error

type RegScanner struct {
	name string
}

func (sc *RegScanner) Reset() *RegScanner {
	sc.name = ""
	return sc
}

func (sc *RegScanner) Scan(state fmt.ScanState, _ rune) error {

	for {
		r, _, err := state.ReadRune()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if r == ',' || r == ' ' || r == ')' {
			state.UnreadRune()
			break
		}
		sc.name = sc.name + string(r)
	}
	return nil
}

func parseRegDeref(str string, ass *Assignment) error {
	var (
		off int64
		reg RegScanner
		n   int
		ok  bool
	)

	if n, _ = fmt.Sscanf(str, "0x%x(%%%s)", &off, &reg); n != 2 {
		if n, _ = fmt.Sscanf(str, "%d(%%%s)", &off, &reg); n != 2 {
			if n, _ = fmt.Sscanf(str, "(%%%s)", reg.Reset()); n != 1 {
				return errNext
			}
		}
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_REG_DEREF
	ass.Off = uint64(off)
	ass.Src, ass.SrcSize, ok = RegOffsetSize(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}
	return nil
}

func parseRegOff(str string, ass *Assignment) error {
	var (
		reg RegScanner
		n   int
		ok  bool
		off int
	)

	if n, _ = fmt.Sscanf(str, "0x%x%%%s", &off, &reg); n != 2 {
		if n, _ = fmt.Sscanf(str, "%d%%%s", &off, reg.Reset()); n != 2 {
			return errNext
		}
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_REG_OFF
	ass.Off = uint64(off)
	ass.Src, ass.SrcSize, ok = RegOffsetSize(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}
	return nil
}

func parseReg(str string, ass *Assignment) error {
	var (
		reg RegScanner
		n   int
		ok  bool
	)

	if n, _ = fmt.Sscanf(str, "%%%s", &reg); n != 1 {
		return errNext
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_REG
	ass.Off = 0
	ass.Src, ass.SrcSize, ok = RegOffsetSize(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}
	return nil
}

func parseConst(str string, ass *Assignment) error {

	var (
		n   int
		off int
	)

	if n, _ = fmt.Sscanf(str, "0x%x", &off); n != 1 {
		if n, _ = fmt.Sscanf(str, "%d", &off); n != 1 {
			return errNext
		}
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_CONST
	ass.Off = uint64(off)
	return nil
}

func ParseAssignment(str string) (*Assignment, error) {
	parsers := []fn{
		parseRegDeref,
		parseRegOff,
		parseReg,
		parseConst,
	}

	ass := &Assignment{}

	s := strings.Split(str, "=")
	if len(s) != 2 {
		return nil, fmt.Errorf("failed to parse assignment '%s'", str)
	}

	var ok bool

	ass.Dst, ass.DstSize, ok = RegOffsetSize(s[0] /* dst */)
	if !ok {
		return nil, fmt.Errorf("failed to parse register '%s'", s[0])
	}

	for _, parse := range parsers {
		err := parse(s[1] /* src */, ass)
		if err == nil {
			return ass, nil
		}
		if !errors.Is(err, errNext) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("failed to parse '%s'", str)
}
