// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"bytes"
	"strings"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/filters"
)

func argsDecoderTrim(r rune) bool {
	return r == 0x00
}

func ArgsDecoder(s string, flags uint32) (string, string) {
	var b []byte
	var cwd string
	var hasCWD int
	args := ""

	b = append(b, 0x00)
	argTokens := bytes.Split(bytes.TrimRightFunc([]byte(s), argsDecoderTrim), b)
	flagsOR := ((flags & api.EventNoCWDSupport) |
		(flags & api.EventErrorCWD) |
		(flags & api.EventRootCWD))
	if flagsOR == 0 {
		hasCWD = 1
	} else {
		hasCWD = 0
	}

	if (flags & api.EventNoCWDSupport) != 0 {
		cwd = ""
	} else if (flags & api.EventErrorCWD) != 0 {
		cwd = ""
	} else if (flags & api.EventRootCWD) != 0 {
		cwd = "/"
	} else if (flags & api.EventProcFS) != 0 {
		cwd = strings.TrimSpace(string(argTokens[len(argTokens)-1]))
	} else {
		cwd = string(argTokens[len(argTokens)-1])
	}

	if len(argTokens) > hasCWD {
		list := make([]string, 0, len(argTokens)-hasCWD)
		for _, a := range argTokens[:len(argTokens)-hasCWD] {
			list = append(list, string(a))
		}
		args = filters.JoinArgs(list)
	}
	return args, cwd
}
