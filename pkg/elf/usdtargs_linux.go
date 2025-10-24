// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Arg parsing entrypoint
func parseArgs(spec *UsdtSpec) error {
	for idx, str := range strings.Split(spec.ArgsStr, " ") {
		arg := &spec.Args[idx]

		for _, parse := range parsers {
			err := parse(str, arg)
			if err == nil {
				break
			}
			if !errors.Is(err, errNext) {
				return err
			}
		}
		arg.Str = str
		spec.ArgsCnt++
	}

	return nil
}

func parseCommon(sz int, arg *UsdtArg) error {
	arg.Signed = sz < 0
	if sz < 0 {
		sz = -sz
	}
	arg.Size = sz

	switch sz {
	case 1, 2, 4, 8:
		arg.Shift = 64 - uint8(sz)*8
	default:
		return fmt.Errorf("wrong sz %d", sz)
	}
	return nil
}

var errNext = errors.New("next")

type fn func(str string, arg *UsdtArg) error

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
		if r == ',' || r == ' ' || r == closingRune {
			state.UnreadRune()
			break
		}
		sc.name = sc.name + string(r)
	}
	return nil
}
