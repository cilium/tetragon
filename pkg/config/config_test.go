// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "config-")
	if err != nil {
		t.Fatalf("cannot create temp. file: %v", err)
	}
	defer func() {
		file.Close()
		os.Remove(file.Name())
	}()

	write := func(data string) {
		file.Truncate(0)
		file.Seek(0, 0)
		_, err = file.WriteString(data)
		if err != nil {
			t.Fatalf("cannot write to temp. file: %v", err)
		}
	}

	actual := Spec{}

	reload := func(_ uint64, spec Spec) {
		actual = spec
	}

	t.Run("disable-kprobe-multi", func(t *testing.T) {
		write(`
options:
  disable-kprobe-multi: true
`)

		cfg := NewConfig(file.Name(), 100*time.Millisecond, reload)

		assert.Equal(t, true, *actual.Options.DisableKprobeMulti)

		write(`
options:
  disable-kprobe-multi: false
`)

		// wait for reconfig
		time.Sleep(500 * time.Millisecond)

		assert.Equal(t, false, *actual.Options.DisableKprobeMulti)

		write(`
options:
`)

		// wait for reconfig
		time.Sleep(500 * time.Millisecond)

		var ptr *bool

		assert.Equal(t, ptr, actual.Options.DisableKprobeMulti)

		cfg.Stop()
	})
}
