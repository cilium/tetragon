// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package asm

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/cilium/tetragon/pkg/cursorparser"
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

// parseRegOff parses register-offset forms "off%reg".
// Examples: "8%rsp", "0x20%rsp", "0x20 %rsp".
func parseRegOff(str string, ass *Assignment) error {
	// Split "off%reg" at the percent marker. There must be a non-empty
	// offset before it and a non-empty register name after it.
	offStr, reg, ok := strings.Cut(str, "%")
	if !ok {
		return errNext
	}

	offStr = strings.TrimSpace(offStr)
	if offStr == "" {
		return errNext
	}
	off, err := parseOffset(offStr)
	if err != nil {
		return errNext
	}

	reg = strings.TrimRightFunc(reg, unicode.IsSpace)
	if reg == "" {
		return errNext
	}

	src, srcSize, ok := RegOffsetSize(reg)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg)
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_REG_OFF
	ass.Off = off
	ass.Src = src
	ass.SrcSize = srcSize
	return nil
}

// parseReg parses register assignment forms "%reg".
// Example: "%rax".
func parseReg(str string, ass *Assignment) error {
	p := cursorparser.New(str)

	// Register assignments must start with a percent marker.
	if !p.Consume('%') {
		return errNext
	}

	// Everything after '%' is the source register.
	reg := strings.TrimRightFunc(p.ReadRest(), unicode.IsSpace)
	if reg == "" {
		return errNext
	}

	src, srcSize, ok := RegOffsetSize(reg)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg)
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_REG
	ass.Off = 0
	ass.Src = src
	ass.SrcSize = srcSize
	return nil
}

// parseConst parses constant assignment forms such as "1" and "-1".
// Constants keep base-0 parsing, so 0x and leading-zero forms are accepted.
// Examples: "1", "-1", "0x20", "010".
func parseConst(str string, ass *Assignment) error {
	uoff, err := parseOffset(strings.TrimSpace(str))
	if err != nil {
		return errNext
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_CONST
	ass.Off = uoff
	return nil
}

// parseOffset parses decimal, hex, octal, signed, and full-width unsigned
// offsets. It intentionally uses strconv base 0, so offsets accept "0x20",
// "010", "-1", and "0xffffffffffffffff" forms.
func parseOffset(str string) (uint64, error) {
	if str == "" {
		return 0, strconv.ErrSyntax
	}

	// Parse negative numbers as int64 first because ParseUint rejects the
	// leading minus sign. The uint64 conversion preserves the two's-complement
	// representation used by the assignment format.
	if strings.HasPrefix(str, "-") {
		off, err := strconv.ParseInt(str, 0, 64)
		if err != nil {
			return 0, err
		}
		return uint64(off), nil
	}

	return strconv.ParseUint(str, 0, 64)
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
