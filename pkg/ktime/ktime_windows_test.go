package ktime

import (
	"testing"
)

func TestKtime(t *testing.T) {
	t1, err := NanoTimeSince(0)
	if err != nil {
		t.Log("FAIL")
	}
	t2, err := NanoTimeSince(0)
	if err != nil {
		t.Log("FAIL")
	}
	t.Log("t2", t2.Nanoseconds())
	t.Log("t1", t1.Nanoseconds())
}

func TestBoottime(t *testing.T) {
	t1, err := DecodeKtime(0, false)
	if err != nil {
		t.Log("FAIL")
	}
	t2, err := DecodeKtime(0, false)
	if err != nil {
		t.Log("FAIL")
	}
	t.Log("t2", t2.Nanosecond())
	t.Log("t1", t1.Nanosecond())
}
