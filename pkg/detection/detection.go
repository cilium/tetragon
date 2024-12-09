// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package detection

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
)

var privilegedExecutionTags = []string{
	// MITRE ATT&CK framework
	"attack.techniques", "attack.T1548", "attack.T1068",
	"attack.tactics", "attack.TA0004",
}

func AddDetectionTagsExec(binaryProp *tetragon.BinaryProperties) []string {
	if binaryProp == nil || binaryProp.PrivilegesChanged == nil ||
		len(binaryProp.PrivilegesChanged) == 0 {
		return nil
	}
	return privilegedExecutionTags
}

func AddDetectionMsgExec(binaryProp *tetragon.BinaryProperties) string {
	if binaryProp == nil || binaryProp.PrivilegesChanged == nil ||
		len(binaryProp.PrivilegesChanged) == 0 {
		return ""
	}

	for _, v := range binaryProp.PrivilegesChanged {
		switch v {
		case tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_CAP:
			return "Privilege Escalation via execution of a binary with file capabilities"
		case tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_SETUID, tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_SETGID:
			return "Privilege Escalation via SUID/SGID binary execution"
		}
	}

	return ""
}
