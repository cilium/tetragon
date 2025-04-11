// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracepoint

import (
	"reflect"
	"testing"
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

	// The standard does not specify if char is signed or not.
	// Historically, it's signed on amd64 and unsigned on arm64.
	// We can't rely on the architecture to determine this as
	// some 6.x kernels on x86_64 have an unsigned char. Also
	// the comm length is sometimes specified as 16 and other
	// times as TASK_COMM_LEN.
	// Let's test all combinations as any working one is a test
	// pass.

	commField := [4]FieldFormat{
		{
			FieldStr: "char comm[16]",
			Offset:   12,
			Size:     16,
			IsSigned: true,
		},
		{
			FieldStr: "char comm[16]",
			Offset:   12,
			Size:     16,
			IsSigned: false,
		},
		{
			FieldStr: "char comm[TASK_COMM_LEN]",
			Offset:   12,
			Size:     16,
			IsSigned: true,
		},
		{
			FieldStr: "char comm[TASK_COMM_LEN]",
			Offset:   12,
			Size:     16,
			IsSigned: false,
		},
	}

	for loop := range 4 {
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
			commField[loop],
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
		if reflect.DeepEqual(&fields, &gt.Format.Fields) {
			break
		} else if loop == 3 {
			t.Logf("Unexpected result:\nexpected (something like):\n%v\ngot:\n%v\n", &fields, &gt.Format.Fields)
			t.Logf("The comm field could have signed equal to 0 or 1.\n")
			t.Logf("The comm field length could be 16 or TASK_COMM_LEN.\n")
			t.Fail()
		}
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
