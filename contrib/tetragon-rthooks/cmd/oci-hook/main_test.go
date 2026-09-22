// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateContainerHookSpec(t *testing.T) {
	ann := map[string]string{"io.kubernetes.cri.sandbox-namespace": nsDefault}
	cases := []struct {
		name    string
		spec    string
		wantErr bool
		wantAnn map[string]string
	}{
		{
			name:    "invalid json",
			spec:    "{",
			wantErr: true,
		},
		{
			name:    "missing root",
			spec:    `{"annotations": {"io.kubernetes.cri.sandbox-namespace": "default"}}`,
			wantErr: true,
			wantAnn: ann,
		},
		{
			name:    "empty root path",
			spec:    `{"root": {}, "annotations": {"io.kubernetes.cri.sandbox-namespace": "default"}}`,
			wantErr: true,
			wantAnn: ann,
		},
		{
			name: "valid",
			spec: `{"root": {"path": "rootfs"}, "linux": {"cgroupsPath": "/kubepods/pod1/c1"}}`,
		},
	}

	oldDisableGrpc := cliConf.DisableGrpc
	cliConf.DisableGrpc = true
	t.Cleanup(func() { cliConf.DisableGrpc = oldDisableGrpc })

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(c.spec), 0o600))
			t.Chdir(dir)

			err, annotations := createContainerHook(slog.New(slog.DiscardHandler))
			require.True(t, c.wantErr == (err != nil), "unexpected failure")
			require.Equal(t, c.wantAnn, annotations)
		})
	}
}
