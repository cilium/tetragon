// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"os"
	"text/template"
)

var (
	tetragonPolicyTesterService = "tetragon-policytester.service"
)

// The ExecStartPre gate waits for the agent to report "running": policytest adds
// a policy and immediately triggers it, and the agent drops the resulting events
// until it starts draining the ring buffers.
var tetragonPolicyTesterServiceTemplate = `
[Unit]
Description=Tetragon policytester
After=tetragon.target
SuccessAction=poweroff
FailureAction=poweroff

[Service]
{{ if .environment -}}
Environment={{ .environment }}
{{ end -}}
ExecStartPre=/bin/sh -c 'until {{ .tetraBinary }} status | grep -q "Health Status: running"; do sleep 2; done'
ExecStart={{ .tetraBinary }} policytest run --bindir {{ .testerProgsDir }} --all-tests --all-params --output json --output-file {{ .resultsDir }}/results.json {{ .policytestArgs }}
Type=oneshot
StandardOutput=tty
# StandardOutput=journal+console
TimeoutStartSec="60min"

[Install]
WantedBy=multi-user.target
`

func makeTetragonPolicyTesterServiceFile(fname string, ptArgs string, environment string) (string, error) {
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0722)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data := map[string]string{
		"tetraBinary":    "/usr/local/bin/tetra",
		"resultsDir":     policytestsVmResultsDir,
		"testerProgsDir": policytestsVmTestProgsDir,
		"policytestArgs": ptArgs,
		"environment":    environment,
	}

	t := template.Must(template.New("tetragon-policytester-service").Parse(tetragonPolicyTesterServiceTemplate))
	if err := t.Execute(f, data); err != nil {
		return "", err
	}
	return fname, nil
}

func mustMakeTetragonPolicyTesterServiceFile(fname string, ptArgs string, environment string) string {
	fname, err := makeTetragonPolicyTesterServiceFile(fname, ptArgs, environment)
	if err != nil {
		panic(err)
	}
	return fname
}
