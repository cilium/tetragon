// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateProcessCacheConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		c       config
		wantErr bool
	}{
		{name: "defaults", c: config{}},
		{name: "ancestors enabled, cache enabled", c: config{EnableProcessAncestors: true}},
		{name: "cache disabled, ancestors disabled", c: config{DisableProcessCache: true}},
		{name: "cache disabled, ancestors enabled", c: config{DisableProcessCache: true, EnableProcessAncestors: true}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateProcessCacheConfig(tc.c)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateExclusiveFlags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		c       config
		wantErr bool
	}{
		{name: "defaults", c: config{}},
		{name: "rb size only", c: config{RBSize: 1}},
		{name: "rb size total only", c: config{RBSizeTotal: 1}},
		{name: "rb size and total", c: config{RBSize: 1, RBSizeTotal: 1}, wantErr: true},
		{name: "execve map entries only", c: config{ExecveMapEntries: 1}},
		{name: "execve map size only", c: config{ExecveMapSize: "1M"}},
		{name: "execve map entries and size", c: config{ExecveMapEntries: 1, ExecveMapSize: "1M"}, wantErr: true},
		{name: "parents map entries only", c: config{ParentsMapEntries: 1}},
		{name: "parents map size only", c: config{ParentsMapSize: "1M"}},
		{name: "parents map entries and size", c: config{ParentsMapEntries: 1, ParentsMapSize: "1M"}, wantErr: true},
		{name: "small progs only", c: config{ForceSmallProgs: true}},
		{name: "large progs only", c: config{ForceLargeProgs: true}},
		{name: "small and large progs", c: config{ForceSmallProgs: true, ForceLargeProgs: true}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateExclusiveFlags(tc.c)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateServerTLSConfig(t *testing.T) {
	t.Parallel()
	const tcp = "0.0.0.0:54321"
	cases := []struct {
		name    string
		c       config
		wantErr bool
	}{
		{name: "disabled", c: config{}},
		{name: "tls only", c: config{ServerAddress: tcp, ServerTLSCertFile: "a", ServerTLSKeyFile: "b"}},
		{name: "cert without key", c: config{ServerAddress: tcp, ServerTLSCertFile: "a"}, wantErr: true},
		{name: "key without cert", c: config{ServerAddress: tcp, ServerTLSKeyFile: "b"}, wantErr: true},
		{name: "mtls ok", c: config{ServerAddress: tcp, ServerTLSCertFile: "a", ServerTLSKeyFile: "b", ServerTLSRequireClientCert: true, ServerTLSClientCAFiles: []string{"c"}}},
		{name: "mtls without cert", c: config{ServerAddress: tcp, ServerTLSRequireClientCert: true, ServerTLSClientCAFiles: []string{"c"}}, wantErr: true},
		{name: "mtls without ca", c: config{ServerAddress: tcp, ServerTLSCertFile: "a", ServerTLSKeyFile: "b", ServerTLSRequireClientCert: true}, wantErr: true},
		{name: "ca without mtls", c: config{ServerAddress: tcp, ServerTLSCertFile: "a", ServerTLSKeyFile: "b", ServerTLSClientCAFiles: []string{"c"}}, wantErr: true},
		{name: "tls with unix address", c: config{ServerAddress: "unix:///run/tetragon.sock", ServerTLSCertFile: "a", ServerTLSKeyFile: "b"}, wantErr: true},
		{name: "tls with empty address", c: config{ServerAddress: "", ServerTLSCertFile: "a", ServerTLSKeyFile: "b"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateServerTLSConfig(tc.c)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
