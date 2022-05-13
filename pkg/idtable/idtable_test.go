// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package idtable

import (
	"testing"
)

type testEntry struct {
	eid EntryID
	s   string
}

func (t *testEntry) SetID(id EntryID) {
	t.eid = id
}

func TestOps(t *testing.T) {
	idt := New()

	checkLen := func(elen int) {
		if l := idt.Len(); l != elen {
			t.Fatalf("Invalid len: %d expecting: %d", l, elen)
		}
	}

	checkGetVal := func(id EntryID, s string) {
		if entry, err := idt.GetEntry(id); err != nil {
			t.Fatalf("checkGetVal failed with error=%s (id=%d, s=%s)", err, id.ID, s)
		} else if val, ok := entry.(*testEntry); !ok {
			t.Fatalf("checkGetVal failed: unexpected type:%T (id=%d, s=%s)", entry, id.ID, s)
		} else if val.s != s {
			t.Fatalf("checkGetVal failed: unexpected value:%s expected %s (id=%d)", val.s, s, id.ID)
		}
	}

	checkRemoveVal := func(id EntryID, s string) {
		if entry, err := idt.RemoveEntry(id); err != nil {
			t.Fatalf("checkGetVal failed with error=%s (id=%d, s=%s)", err, id.ID, s)
		} else if val, ok := entry.(*testEntry); !ok {
			t.Fatalf("checkGetVal failed: unexpected type:%T (id=%d, s=%s)", entry, id.ID, s)
		} else if val.s != s {
			t.Fatalf("checkGetVal failed: unexpected value:%s expected %s (id=%d)", val.s, s, id.ID)
		}
	}

	checkGetValError := func(id EntryID) {
		if entry, err := idt.GetEntry(id); err == nil {
			t.Fatalf("checkGetVal expected error but got actual value: %+v", entry)
		}
	}

	checkLen(0)
	e0 := testEntry{eid: UninitializedEntryID, s: "e0"}
	idt.AddEntry(&e0)
	checkGetVal(e0.eid, "e0")

	e1 := testEntry{eid: UninitializedEntryID, s: "e1"}
	idt.AddEntry(&e1)
	checkLen(2)
	checkGetVal(e1.eid, "e1")
	checkGetVal(e0.eid, "e0")

	checkRemoveVal(e0.eid, "e0")
	checkLen(1)
	checkGetValError(e0.eid)

	e2 := testEntry{eid: UninitializedEntryID, s: "e2"}
	idt.AddEntry(&e2)
	checkLen(2)
	checkGetVal(e1.eid, "e1")
	checkGetVal(e2.eid, "e2")
}
