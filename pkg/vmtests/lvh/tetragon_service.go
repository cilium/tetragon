// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package lvh

import (
	"bytes"
	"os"
	"path/filepath"
	"text/template"
)

// TetragonService is the unit that runs the agent in the VM.
const TetragonService = "tetragon.service"

var tetragonServiceTemplate = `
[Unit]
Description=Tetragon eBPF-based Security Observability and Runtime Enforcement
DefaultDependencies=no
After=network.target local-fs.target

[Service]
Environment="PATH=/usr/local/lib/tetragon/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
User=root
Group=root
ExecStart={{ .tetragonBinary }} --bpf-lib {{ .tetragonBpfLib }} {{ .additionalArgs }}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

// TetragonServiceFile writes the tetragon unit to fname and returns fname.
func TetragonServiceFile(fname, additionalArgs string) (string, error) {
	return WriteUnit(fname, tetragonServiceTemplate, map[string]string{
		"tetragonBinary": "/usr/local/bin/tetragon",
		"tetragonBpfLib": "/usr/local/lib/tetragon/bpf",
		"additionalArgs": additionalArgs,
	})
}

// WriteUnit renders the systemd unit template with data into fname and
// returns fname.
func WriteUnit(fname, tmpl string, data map[string]string) (string, error) {
	t, err := template.New(filepath.Base(fname)).Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	if err := os.WriteFile(fname, b.Bytes(), 0644); err != nil {
		return "", err
	}
	return fname, nil
}
