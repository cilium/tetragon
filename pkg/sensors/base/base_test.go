// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	kallsymsAcct  = "ffffffff81000000 T acct_process\n"
	kallsymsCtty  = "ffffffff81000100 T disassociate_ctty\n"
	kallsymsOther = "ffffffff81000200 T some_other_function\n"
)

type setExitProbeCase struct {
	name     string
	kallsyms *string
	attach   string // expected probe, empty if setExitProbe must fail
}

// setExitProbeTests lists the kallsyms contents setExitProbe is run against.
// A nil kallsyms means the file does not exist.
var setExitProbeTests = []setExitProbeCase{
	{"both symbols prefer acct_process", new(kallsymsOther + kallsymsCtty + kallsymsAcct), "acct_process"},
	{"only acct_process", new(kallsymsOther + kallsymsAcct), "acct_process"},
	{"only disassociate_ctty", new(kallsymsOther + kallsymsCtty), "disassociate_ctty"},
	{"neither symbol", new(kallsymsOther), ""},
	{"empty kallsyms", new(""), ""},
	{"unreadable kallsyms", nil, ""},
}

func TestSetExitProbe(t *testing.T) {
	savedAttach, savedLabel := Exit.Attach, Exit.Label
	t.Cleanup(func() { Exit.Attach, Exit.Label = savedAttach, savedLabel })

	for _, tc := range setExitProbeTests {
		t.Run(tc.name, func(t *testing.T) { runSetExitProbeCase(t, tc) })
	}
}

func runSetExitProbeCase(t *testing.T, tc setExitProbeCase) {
	Exit.Attach, Exit.Label = "unset", "unset"
	path := filepath.Join(t.TempDir(), "kallsyms")
	if tc.kallsyms != nil {
		require.NoError(t, os.WriteFile(path, []byte(*tc.kallsyms), 0o600))
	}
	err := setExitProbe(path)
	if tc.attach == "" {
		require.Error(t, err)
		// A failure must not leave a half-configured exit probe behind.
		require.Equal(t, "unset", Exit.Attach)
		require.Equal(t, "unset", Exit.Label)
		return
	}
	require.NoError(t, err)
	require.Equal(t, tc.attach, Exit.Attach)
	require.Equal(t, "kprobe/"+tc.attach, Exit.Label)
}
