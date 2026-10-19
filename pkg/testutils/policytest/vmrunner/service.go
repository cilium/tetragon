// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package vmrunner

import "github.com/cilium/tetragon/pkg/vmtests/lvh"

const policytesterService = "tetragon-policytester.service"

// The ExecStartPre gate waits for the agent to report "running": policytest adds
// a policy and immediately triggers it, and the agent drops the resulting events
// until it starts draining the ring buffers. ExecStopPost records how tetra
// ended, so the host can tell a finished run from one that died halfway.
const policytesterServiceTemplate = `
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
ExecStart={{ .tetraBinary }} policytest run --bindir {{ .testerProgsDir }} --output json --output-file {{ .resultsDir }}/results.json {{ .policytestArgs }}
ExecStopPost=/bin/sh -c 'echo "$SERVICE_RESULT $EXIT_CODE $EXIT_STATUS" > {{ .resultsDir }}/{{ .statusFile }}'
Type=oneshot
StandardOutput=tty
# StandardOutput=journal+console
TimeoutStartSec="60min"

[Install]
WantedBy=multi-user.target
`

// policytesterServiceFile writes the unit that runs the tests at boot to
// fname and returns fname.
func policytesterServiceFile(fname string, ptArgs string, environment string) (string, error) {
	return lvh.WriteUnit(fname, policytesterServiceTemplate, map[string]string{
		"tetraBinary":    "/usr/local/bin/tetra",
		"resultsDir":     resultsVMDir,
		"statusFile":     statusFile,
		"testerProgsDir": testerProgsVMDir,
		"policytestArgs": ptArgs,
		"environment":    environment,
	})
}
