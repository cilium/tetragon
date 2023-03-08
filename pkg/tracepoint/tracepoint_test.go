// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracepoint

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/cilium/tetragon/pkg/kernels"
)

func TestTracepointLoadFormat(t *testing.T) {
	gt := Tracepoint{
		Subsys: "task",
		Event:  "task_newtask",
	}

	err := gt.LoadFormat()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// the standard does not specify if char is signed or not
	// historically, it's signed on amd64 and unsigned on arm64
	isCharSigned := true
	if runtime.GOARCH == "arm64" {
		isCharSigned = false
	}

	var commField FieldFormat
	if kernels.MinKernelVersion("5.17.0") {
		commField = FieldFormat{
			FieldStr: "char comm[TASK_COMM_LEN]",
			Offset:   12,
			Size:     16,
			IsSigned: isCharSigned,
		}
	} else {
		commField = FieldFormat{
			FieldStr: "char comm[16]",
			Offset:   12,
			Size:     16,
			IsSigned: isCharSigned,
		}
	}

	fields := []FieldFormat{
		FieldFormat{
			FieldStr: "unsigned short common_type",
			Offset:   0,
			Size:     2,
			IsSigned: false,
		},
		FieldFormat{
			FieldStr: "unsigned char common_flags",
			Offset:   2,
			Size:     1,
			IsSigned: false,
		},
		FieldFormat{
			FieldStr: "unsigned char common_preempt_count",
			Offset:   3,
			Size:     1,
			IsSigned: false,
		},
		FieldFormat{
			FieldStr: "int common_pid",
			Offset:   4,
			Size:     4,
			IsSigned: true,
		},
		FieldFormat{
			FieldStr: "pid_t pid",
			Offset:   8,
			Size:     4,
			IsSigned: true,
		},
		commField,
		FieldFormat{
			FieldStr: "unsigned long clone_flags",
			Offset:   32,
			Size:     8,
			IsSigned: false,
		},
		FieldFormat{
			FieldStr: "short oom_score_adj",
			Offset:   40,
			Size:     2,
			IsSigned: true,
		},
	}

	// NB: ID does not seem to be the same across systems, so we check only fields
	if !reflect.DeepEqual(&fields, &gt.Format.Fields) {
		t.Logf("Unexpected result:\nexpected:%v\ngot     :%v\n", &fields, &gt.Format.Fields)
		t.Fail()
	}
}

func TestTracepointsAll(t *testing.T) {

	tracepoints, err := GetAllTracepoints()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	for _, tp := range tracepoints {
		err := tp.LoadFormat()
		if err != nil {
			t.Logf("failed to load information for %s/%s: %s", tp.Subsys, tp.Event, err)
			t.Fail()
		}
		for _, field := range tp.Format.Fields {
			err := field.ParseField()
			if err != nil {
				t.Logf("FYI: failed to parse field '%s' of %s/%s: %s", field.FieldStr, tp.Subsys, tp.Event, err)
				// NB: we do not support all different types yet, so we dont fail here.
				// t.Fail()
			}
		}
	}
}
