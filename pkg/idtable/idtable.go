// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package idtable

import (
	"fmt"
)

// idtable implements a simple id table. Any required synchronization needs to
// happen on the caller.

var (
	// UninitializedEntryID provides an invalid value for EntryID (since its default value is valid)
	UninitializedEntryID = EntryID{-1}
)

// EntryID is a table entry identifier
// NB: we wrap this to get some type safety for the SetID() methof of the Entry
// interface
type EntryID struct {
	ID int
}

// Entry is an interface for table entries
type Entry interface {
	// SetID will set the id of an entry on a table when AddEntry() is
	// called. The id can be used in the GetEntry() and RemoveEntry() calls.
	SetID(id EntryID)
}

// invalidEntry is a special internal type to indicate invalid entries on the
// table so that the can be re-used.
type invalidEntry struct{}

func (invalidEntry) SetID(_ EntryID) {}

// Table is the id table
type Table struct {
	arr []Entry
}

// New allocates a new id table
func New() *Table {
	return &Table{}
}

// findEmpty will find an empty slot in the table, or create a new one
func (t *Table) findEmpty() int {
	// find an empty slot
	for i := range t.arr {
		if _, invalid := t.arr[i].(invalidEntry); invalid {
			return i
		}
	}

	// if no empty slot exist, append a new slot
	idx := len(t.arr)
	t.arr = append(t.arr, invalidEntry{})
	return idx
}

// AddEntry will add an entry to the table. The SetID() method will be called
// with the id for the entry.
func (t *Table) AddEntry(entry Entry) {
	idx := t.findEmpty()
	t.arr[idx] = entry
	entry.SetID(EntryID{idx})
	return
}

func (t *Table) getValidEntryIndex(id EntryID) (int, error) {
	xid := id.ID
	if xid >= len(t.arr) || xid < 0 {
		return -1, fmt.Errorf("invalid id (ID=%d)", xid)
	}

	switch t.arr[xid].(type) {
	case invalidEntry:
		return -1, fmt.Errorf("invalid id (ID=%d/invalid entry)", xid)
	default:
		return xid, nil
	}
}

// GetEntry returns an entry or an error
func (t *Table) GetEntry(id EntryID) (Entry, error) {
	idx, err := t.getValidEntryIndex(id)
	if err != nil {
		return nil, err
	}
	return t.arr[idx], nil
}

// RemoveEntry removes an entry and returns it (or an error if entry does not exist)
func (t *Table) RemoveEntry(id EntryID) (Entry, error) {
	idx, err := t.getValidEntryIndex(id)
	if err != nil {
		return nil, err
	}
	entry := t.arr[idx]
	t.arr[idx] = invalidEntry{}
	entry.SetID(UninitializedEntryID)
	return entry, nil
}

// Len returns the number of entries
func (t *Table) Len() int {
	count := 0
	for i := range t.arr {
		if _, invalid := t.arr[i].(invalidEntry); !invalid {
			count++
		}
	}
	return count
}
