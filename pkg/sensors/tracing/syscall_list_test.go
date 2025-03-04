// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/cilium/tetragon/pkg/syscallinfo"
	"github.com/stretchr/testify/require"
)

func defABI(t *testing.T) string {
	abi, err := syscallinfo.DefaultABI()
	require.Nil(t, err)
	return abi
}

func defSysCallPrefix(t *testing.T) string {
	switch a := runtime.GOARCH; a {
	case "amd64":
		return "__x64_"
	case "arm64":
		return "__arm64_"
	default:
		t.Fatalf("unsupported arch: %s", a)
		return ""
	}
}

func TestParseSyscallValue(t *testing.T) {
	type testCase struct {
		val             string
		expError        bool
		expABI, expName string
	}

	tcs := []testCase{
		{val: "sys_dup", expError: false, expABI: defABI(t), expName: "sys_dup"},
		{val: "i386/sys_dup", expError: false, expABI: "i386", expName: "sys_dup"},
		{val: "__ia32_sys_dup", expError: false, expABI: "i386", expName: "sys_dup"},
		{val: "x64/sys_dup", expError: false, expABI: "x64", expName: "sys_dup"},
		{val: "__x64_sys_dup", expError: false, expABI: "x64", expName: "sys_dup"},
		{val: "__foo_sys_dup", expError: false, expABI: defABI(t), expName: "__foo_sys_dup"},
	}

	for _, tc := range tcs {
		abi, name, err := parseSyscallValue(SyscallVal(tc.val))
		if tc.expError {
			require.Error(t, err, fmt.Sprintf("tc: %+v", tc))
		} else {
			require.Nil(t, err)
			require.Equal(t, tc.expABI, abi)
			require.Equal(t, tc.expName, name)
		}
	}
}

func TestSyscallValSymbol(t *testing.T) {
	type testCase struct {
		val         string
		symExpError bool
		symExpVal   string
	}

	tcs := []testCase{
		{val: "sys_dup", symExpError: false, symExpVal: defSysCallPrefix(t) + "sys_dup"},
		{val: "i386/sys_dup", symExpError: false, symExpVal: "__ia32_sys_dup"},
		{val: "__ia32_sys_dup", symExpError: false, symExpVal: "__ia32_sys_dup"},
		{val: "x64/sys_dup", symExpError: false, symExpVal: "__x64_sys_dup"},
		{val: "__foo_dup", symExpError: true},
		{val: "arm64/sys_dup", symExpError: false, symExpVal: "__arm64_sys_dup"},
	}

	for _, tc := range tcs {
		v := SyscallVal(tc.val)
		sym, err := v.Symbol()
		if tc.symExpError {
			require.Error(t, err)
		} else {
			require.Nil(t, err)
			require.Equal(t, tc.symExpVal, sym)
		}
	}
}
