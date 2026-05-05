// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
