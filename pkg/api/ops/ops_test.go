// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package ops

import (
	"testing"
)

func TestCgroupOpCode(t *testing.T) {
	testcases := map[CgroupOpCode]string{
		MSG_OP_CGROUP_UNDEF:       "Undef",
		MSG_OP_CGROUP_MKDIR:       "CgroupMkdir",
		MSG_OP_CGROUP_RMDIR:       "CgroupRmdir",
		MSG_OP_CGROUP_RELEASE:     "CgroupRelease",
		MSG_OP_CGROUP_ATTACH_TASK: "CgroupAttachTask",
	}

	for op, str := range testcases {
		if CgroupOpCode(op).String() != str {
			t.Errorf("CgroupOpCode mismatch - want:%s  got:%s", str, CgroupOpCode(op).String())
		}
	}
}

func TestCgroupState(t *testing.T) {
	testcases := map[CgroupState]string{
		CGROUP_UNTRACKED:    "Untracked",
		CGROUP_NEW:          "New",
		CGROUP_RUNNING:      "Running",
		CGROUP_RUNNING_PROC: "RunningProc",
	}

	if len(testcases) != int(_CGROUP_STATE_MAX) {
		t.Errorf("CgroupState values mismatch, missing states")
	}

	for op, str := range testcases {
		if CgroupState(op).String() != str {
			t.Errorf("CgroupState mismatch - want:%s  got:%s", str, CgroupState(op).String())
		}
	}
}
