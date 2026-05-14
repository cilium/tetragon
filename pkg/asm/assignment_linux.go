// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package asm

import (
	"errors"
	"fmt"
	"strconv"
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

func parseRegDeref(str string, ass *Assignment) error {
	var (
		off uint64
		err error
		ok  bool
	)

	if !strings.HasSuffix(str, ")") {
		return errNext
	}

	open := strings.Index(str, "(%")
	if open < 0 {
		return errNext
	}

	reg := str[open+2 : len(str)-1]
	if reg == "" {
		return errNext
	}

	if offStr := str[:open]; offStr != "" {
		off, err = parseOffset(offStr)
		if err != nil {
			return errNext
		}
	}

	src, srcSize, ok := RegOffsetSize(reg)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg)
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_REG_DEREF
	ass.Off = off
	ass.Src = src
	ass.SrcSize = srcSize
	return nil
}

func parseRegOff(str string, ass *Assignment) error {
	var (
		ok  bool
		off uint64
		err error
	)

	percent := strings.LastIndexByte(str, '%')
	if percent <= 0 || percent == len(str)-1 {
		return errNext
	}

	off, err = parseOffset(str[:percent])
	if err != nil {
		return errNext
	}

	reg := str[percent+1:]
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

func parseReg(str string, ass *Assignment) error {
	var (
		ok bool
	)

	if !strings.HasPrefix(str, "%") || len(str) == 1 {
		return errNext
	}

	reg := str[1:]
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

func parseConst(str string, ass *Assignment) error {

	var (
		uoff uint64
		soff int64
		err  error
	)

	if uoff, err = strconv.ParseUint(str, 0, 64); err != nil {
		if soff, err = strconv.ParseInt(str, 0, 64); err != nil {
			return errNext
		}
		uoff = uint64(soff)
	}

	ass.Type = ASM_ASSIGNMENT_TYPE_CONST
	ass.Off = uoff
	return nil
}

func parseOffset(str string) (uint64, error) {
	if str == "" {
		return 0, strconv.ErrSyntax
	}

	if strings.HasPrefix(str, "-") {
		off, err := strconv.ParseInt(str, 0, 64)
		if err != nil {
			return 0, err
		}
		return uint64(off), nil
	}

	off, err := strconv.ParseUint(str, 0, 64)
	if err == nil {
		return off, nil
	}

	soff, serr := strconv.ParseInt(str, 0, 64)
	if serr != nil {
		return 0, err
	}
	return uint64(soff), nil
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
