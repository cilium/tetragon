// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fileutils

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegularFilePerms(t *testing.T) {
	type progTest struct {
		in   string
		want os.FileMode
		err  bool
	}

	testcases := []progTest{
		{
			in:   "",
			want: os.FileMode(regularSecure),
			err:  true,
		},
		{
			in:   "00000",
			want: os.FileMode(regularSecure),
			err:  false,
		},
		{
			in:   "0002",
			want: os.FileMode(regularSecure),
			err:  false,
		},
		{
			in:   "0004",
			want: os.FileMode(syscall.S_IFREG | 0604),
			err:  false,
		},
		{
			in:   "0006",
			want: os.FileMode(syscall.S_IFREG | 0604),
			err:  false,
		},
		{
			in:   "0047",
			want: os.FileMode(syscall.S_IFREG | 0644),
			err:  false,
		},
		{
			in:   "0070",
			want: os.FileMode(syscall.S_IFREG | 0660),
			err:  false,
		},
		{
			in:   "0050",
			want: os.FileMode(syscall.S_IFREG | 0640),
			err:  false,
		},
		{
			in:   "0700",
			want: os.FileMode(syscall.S_IFREG | 0600),
			err:  false,
		},
		{
			in:   "0200",
			want: os.FileMode(syscall.S_IFREG | 0600),
			err:  false,
		},
		{
			in:   "0040000",
			want: os.FileMode(syscall.S_IFREG | 0600),
			err:  false,
		},
		{
			in:   "0044600",
			want: os.FileMode(syscall.S_IFREG | 0600),
			err:  false,
		},
		{
			in:   "0016622",
			want: os.FileMode(syscall.S_IFREG | 0620),
			err:  false,
		},
	}

	for i, test := range testcases {
		out, err := RegularFilePerms(test.in)
		require.Truef(t, out.IsRegular(), "Failed returned filemode is not for regular files")
		if test.err == true {
			require.Errorf(t, err, "Failed at test %d", i+1)
		}
		require.Equalf(t, test.want, out, "Failed at test %d   - expected:%v - actual:%v", i+1, test.want, out)
	}
}
