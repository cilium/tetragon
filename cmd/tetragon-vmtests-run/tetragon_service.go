// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"os"
	"text/template"
)

var (
	tetragonService = "tetragon.service"
)

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

func makeTetragonServiceFile(fname, additionalArgs string) (string, error) {
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0722)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data := map[string]string{
		"tetragonBinary": "/usr/local/bin/tetragon",
		"tetragonBpfLib": "/usr/local/lib/tetragon/bpf",
		"additionalArgs": additionalArgs,
	}

	t := template.Must(template.New("tetragon-service").Parse(tetragonServiceTemplate))
	if err := t.Execute(f, data); err != nil {
		return "", err
	}
	return fname, nil
}

func mustMakeTetragonServiceFile(fname, additionalArgs string) string {
	fname, err := makeTetragonServiceFile(fname, additionalArgs)
	if err != nil {
		panic(err)
	}
	return fname
}
