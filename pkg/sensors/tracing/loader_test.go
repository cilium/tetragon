// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/matchers/bytesmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

type note struct {
	Namesz uint32
	Descsz uint32
	Typ    uint32
}

func align(v, a uint32) uint32 {
	return ((v + 1) / a) * a
}

func parseNote(dat []byte) ([]byte, bool) {
	var note note

	dr := bytes.NewReader(dat)

	for {
		if err := binary.Read(dr, binary.LittleEndian, &note); err != nil {
			return []byte{}, false
		}

		name := make([]byte, align(note.Namesz, 4))
		if err := binary.Read(dr, binary.LittleEndian, name); err != nil {
			return []byte{}, false
		}

		desc := make([]byte, align(note.Descsz, 4))
		if err := binary.Read(dr, binary.LittleEndian, desc); err != nil {
			return []byte{}, false
		}

		if note.Typ == 3 &&
			note.Namesz == 4 &&
			bytes.Equal(name, []byte{'G', 'N', 'U', 0}) &&
			note.Descsz > 0 && note.Descsz <= 20 {
			return desc, true
		}
	}
}

func parseBuildId(filename string) ([]byte, error) {
	f, err := elf.Open(filename)
	if err != nil {
		return []byte{}, err
	}
	defer f.Close()

	for _, ph := range f.Progs {
		if ph.Type != elf.PT_NOTE {
			continue
		}
		dat := make([]byte, ph.Filesz)
		_, err := io.ReadFull(ph.Open(), dat)
		if err != nil {
			continue
		}
		bid, ok := parseNote(dat)
		if ok {
			return bid, nil
		}
	}
	return []byte{}, nil
}

func TestLoader(t *testing.T) {
	if !hasLoaderEvents() {
		t.Skip("no support for loader events")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	loaderHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "loader"
spec:
  loader: true
`
	loaderConfigHook := []byte(loaderHook)
	err := os.WriteFile(testConfigFile, loaderConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	id, err := parseBuildId(testNop)
	if err != nil {
		t.Fatalf("Failed to ParseBuildId: %v\n", err)
	}

	loaderChecker := ec.NewProcessLoaderChecker("").
		WithBuildid(bytesmatcher.Full(id)).
		WithPath(sm.Full(testNop))

	checker := ec.NewUnorderedEventChecker(loaderChecker)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
