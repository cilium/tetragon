// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/testutils"
)

func TestDynamicSOResolveDep(t *testing.T) {
	binary := testutils.RepoRootPath("contrib/tester-progs/uprobe-simple")

	libc, err := resolveDep(binary, libcName)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(libc, "/"+libcName), "unexpected libc path %q", libc)

	_, err = resolveDep(binary, "libdoesnotexist.so.1")
	require.Error(t, err)

	// virtual DSOs have no "=>" in ldd output, so they are not resolved
	_, err = resolveDep(binary, "linux-vdso.so.1")
	require.Error(t, err)

	_, err = resolveDep("/does/not/exist", libcName)
	require.Error(t, err)
}

func TestDynamicSOIsSODynamic(t *testing.T) {
	tests := []struct {
		name   string
		action v1alpha1.ActionSelector
		want   bool
	}{
		{
			name:   "override with sopath and symbol",
			action: v1alpha1.ActionSelector{Action: "Override", SoPath: "/lib.so", ArgNewSymbol: "sym"},
			want:   true,
		},
		{
			name:   "override with sopath and addr",
			action: v1alpha1.ActionSelector{Action: "Override", SoPath: "/lib.so", ArgNewAddr: 0x1000},
			want:   true,
		},
		{
			name:   "override with sopath and offset",
			action: v1alpha1.ActionSelector{Action: "Override", SoPath: "/lib.so", ArgNewOffset: 0x1000},
			want:   true,
		},
		{
			name:   "override with sopath only",
			action: v1alpha1.ActionSelector{Action: "Override", SoPath: "/lib.so"},
			want:   false,
		},
		{
			name:   "override without sopath",
			action: v1alpha1.ActionSelector{Action: "Override", ArgNewSymbol: "sym"},
			want:   false,
		},
		{
			name:   "non-override action with sopath",
			action: v1alpha1.ActionSelector{Action: "Post", SoPath: "/lib.so", ArgNewSymbol: "sym"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isSODynamicAction(tt.action))

			selectors := []v1alpha1.KProbeSelector{
				{MatchActions: []v1alpha1.ActionSelector{{Action: "Post"}}},
				{MatchActions: []v1alpha1.ActionSelector{{Action: "Post"}, tt.action}},
			}
			require.Equal(t, tt.want, IsSODynamic(selectors))
		})
	}

	require.False(t, IsSODynamic(nil))
}

func TestDynamicSOValidate(t *testing.T) {
	soAction := func(sopath string) v1alpha1.ActionSelector {
		return v1alpha1.ActionSelector{Action: "Override", SoPath: sopath, ArgNewSymbol: "sym"}
	}
	selectors := func(actions ...v1alpha1.ActionSelector) []v1alpha1.KProbeSelector {
		var ret []v1alpha1.KProbeSelector
		for _, a := range actions {
			ret = append(ret, v1alpha1.KProbeSelector{MatchActions: []v1alpha1.ActionSelector{a}})
		}
		return ret
	}

	maxBase := strings.Repeat("b", processapi.SONAME_MAX-1)
	maxPath := "/" + strings.Repeat("p", processapi.SOPATH_MAX-len(maxBase)-3) + "/" + maxBase

	tests := []struct {
		name       string
		selectors  []v1alpha1.KProbeSelector
		wantErrMsg string
	}{
		{
			name: "no selectors",
		},
		{
			name:      "no sopath actions",
			selectors: selectors(v1alpha1.ActionSelector{Action: "Post"}),
		},
		{
			name:      "single sopath action",
			selectors: selectors(soAction("/usr/lib/libfoo.so")),
		},
		{
			name:      "sopath and basename at max length",
			selectors: selectors(soAction(maxPath)),
		},
		{
			name:       "sopath too long",
			selectors:  selectors(soAction(maxPath + "x")),
			wantErrMsg: "exceeds maximum length",
		},
		{
			name:       "basename too long",
			selectors:  selectors(soAction("/usr/lib/" + maxBase + "x")),
			wantErrMsg: "basename(sopath)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSODynamic(&v1alpha1.UProbeSpec{Selectors: tt.selectors})
			if tt.wantErrMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

func TestDynamicSOInit(t *testing.T) {
	binary := testutils.RepoRootPath("contrib/tester-progs/uprobe-simple")
	lib := testutils.RepoRootPath("contrib/tester-progs/libuprobe.so")
	const sym = "uprobe_test_lib"

	f, err := elf.OpenSafeELFFile(lib)
	require.NoError(t, err)
	symAddr, err := f.Address(sym)
	require.NoError(t, err)
	symOff, err := f.Offset(sym)
	require.NoError(t, err)
	f.Close()

	tests := []struct {
		name     string
		action   v1alpha1.ActionSelector
		wantAddr uint64
		wantErr  bool
	}{
		{
			name:     "symbol",
			action:   v1alpha1.ActionSelector{Action: "Override", SoPath: lib, ArgNewSymbol: sym},
			wantAddr: symAddr,
		},
		{
			name:     "address",
			action:   v1alpha1.ActionSelector{Action: "Override", SoPath: lib, ArgNewAddr: 0x1234},
			wantAddr: 0x1234,
		},
		{
			name:     "offset",
			action:   v1alpha1.ActionSelector{Action: "Override", SoPath: lib, ArgNewOffset: int64(symOff)},
			wantAddr: symAddr,
		},
		{
			name:    "unknown symbol",
			action:  v1alpha1.ActionSelector{Action: "Override", SoPath: lib, ArgNewSymbol: "does_not_exist"},
			wantErr: true,
		},
		{
			name:    "offset outside executable segments",
			action:  v1alpha1.ActionSelector{Action: "Override", SoPath: lib, ArgNewOffset: 0xffffffff},
			wantErr: true,
		},
		{
			name:    "missing sopath",
			action:  v1alpha1.ActionSelector{Action: "Override", SoPath: "/does/not/exist.so", ArgNewSymbol: sym},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dynOv DynamicOverride
			err := dynOv.Init(&tt.action, binary)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, lib, dynOv.Library)
			require.Equal(t, tt.wantAddr, dynOv.Addr)
			require.NotZero(t, dynOv.offsets.MmapOff)
			require.NotZero(t, dynOv.offsets.DlopenOff)
		})
	}

	t.Run("binary without libc", func(t *testing.T) {
		var dynOv DynamicOverride
		act := v1alpha1.ActionSelector{Action: "Override", SoPath: lib, ArgNewSymbol: sym}
		require.Error(t, dynOv.Init(&act, "/does/not/exist"))
	})
}

func TestDynamicSOPopulateUprobeRegs(t *testing.T) {
	dynOv := DynamicOverride{
		Library: "/usr/lib/libfoo.so.1",
		Addr:    0x1122,
		offsets: libcOffsets{MmapOff: 0x3344, DlopenOff: 0x5566},
	}

	regs := dynOv.PopulateUprobeRegs()

	wantPath := []byte("/usr/lib/libfoo.so.1\000")
	require.Equal(t, uint32(len(wantPath)), regs.SopathLen)
	require.Equal(t, wantPath, regs.Sopath[:len(wantPath)])
	require.Equal(t, wantPath[:len(wantPath)-1], regs.Sopath[:bytes.IndexByte(regs.Sopath[:], 0)])

	wantName := []byte("libfoo.so.1\000")
	require.Equal(t, wantName, regs.SoName[:len(wantName)])

	require.Equal(t, uint64(0x1122), regs.SymAddr)
	require.Equal(t, uint64(0x3344), regs.MmapAddr)
	require.Equal(t, uint64(0x5566), regs.DlopenAddr)
	require.Zero(t, regs.Cnt)
}
