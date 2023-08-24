// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"testing"

	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func Fuzz_parseString(f *testing.F) {
	f.Fuzz(func(t *testing.T, input []byte) {
		reader := bytes.NewReader(input)
		parseString(reader)
	})
}

func Test_parseString(t *testing.T) {
	tests := []struct {
		name    string
		input   bytes.Reader
		want    string
		wantErr bool
	}{
		{"normal", *bytes.NewReader([]byte{6, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}), "pizza", false},
		{"shortened", *bytes.NewReader([]byte{3, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}), "piz", false},
		{"too large", *bytes.NewReader([]byte{0, 0, 0, 1, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"error code -2", *bytes.NewReader([]byte{254, 255, 255, 255, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"negative size", *bytes.NewReader([]byte{253, 255, 255, 255, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"missing content", *bytes.NewReader([]byte{1, 0, 0, 0}), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseString(&tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error = %s, wantErr %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
	t.Run("remove trailing null byte", func(t *testing.T) {
		out, err := parseString(bytes.NewReader([]byte{6, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}))
		if err != nil {
			t.Errorf("unexpected error %v", err)
		}
		if out != "pizza" {
			t.Errorf("got %q, want %q", out, "pizza")
		}
	})
}

func Test_SensorPostUnloadHook(t *testing.T) {
	if genericKprobeTable.Len() != 0 {
		t.Errorf("genericKprobeTable expected initial length: 0, got: %d", genericKprobeTable.Len())
	}

	// we use createGenericKprobeSensor because it's where the PostUnloadHook is
	// created. It would be technically more correct if it was added just after
	// insertion in the table in AddKprobe, but this is done by the caller to
	// have just PostUnloadHook that regroups all the potential multiple kprobes
	// contained in one sensor.
	sensor, err := createGenericKprobeSensor("test_sensor", []v1alpha1.KProbeSpec{
		{
			Call:    "test_symbol",
			Syscall: false,
		},
	}, 0, "test_policy", nil)
	if err != nil {
		t.Errorf("createGenericKprobeSensor err expected: nil, got: %s", err)
	}

	if genericKprobeTable.Len() != 1 {
		t.Errorf("genericKprobeTable expected length: 1, got: %d", genericKprobeTable.Len())
	}

	// the return sensor entry does not expose anything publicly so we cannot
	// check anything more than the length of the table, hopefully GetEntry on a
	// non-existing ID will return an error
	_, err = genericKprobeTable.GetEntry(idtable.EntryID{ID: 0})
	if err != nil {
		t.Errorf("genericKprobeTable.GetEntry err expected: nil, got: %s", err)
	}

	// For testing purposes, we simulate that the sensor was loaded, because
	// otherwise, Unload will immediately exit when seeing that this sensor was
	// never loaded
	sensor.Loaded = true

	// Unload should call the PostUnloadHook that was set in
	// createGenericKprobeSensor and do the cleanup
	err = sensor.Unload()
	if err != nil {
		t.Errorf("sensor.Unload err expected: nil, got: %s", err)
	}

	// Table implem detail: the entry still technically exists in the table but
	// is invalid, thus is not taken into account in the length
	if genericKprobeTable.Len() != 0 {
		t.Errorf("genericKprobeTable expected length after cleanup: 0, got: %d", genericKprobeTable.Len())
	}
}
