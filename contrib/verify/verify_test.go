// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/stretchr/testify/require"
)

const (
	tetragondir = "/var/lib/tetragon"
)

func TestVerifyTetragonPrograms(t *testing.T) {

	tetragonDir := os.Getenv("TETRAGONDIR")
	if tetragonDir == "" {
		tetragonDir = tetragondir
	}

	files, err := os.ReadDir(tetragonDir)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	for _, file := range files {
		fileName := file.Name()
		if file.IsDir() || filepath.Ext(fileName) != ".o" {
			continue
		}

		// Alignchecker is not a bpf program, so ignore it
		if strings.HasPrefix(fileName, "bpf_alignchecker") {
			continue
		}

		// Globals is just for testing, so ignore it
		if strings.HasPrefix(fileName, "bpf_alignchecker") {
			continue
		}

		// Generic tracepoint needs more complex userspace logic to load, so ignore it
		if strings.HasPrefix(fileName, "bpf_generic_tracepoint") {
			continue
		}

		// Multi kprobe support is still not widely around, skip the object
		if strings.HasPrefix(fileName, "bpf_multi_") {
			continue
		}

		// Skip v6.1 objects check for kernel < 6.1
		if strings.HasSuffix(fileName, "61.o") && !kernels.MinKernelVersion("6.1") {
			continue
		}

		// Skip v5.11 objects check for kernel < 5.11
		if strings.HasSuffix(fileName, "511.o") && !kernels.MinKernelVersion("5.11") {
			continue
		}

		// Skip bpf_loader for kernel < 5.19
		if strings.HasPrefix(fileName, "bpf_loader") && !kernels.MinKernelVersion("5.19") {
			continue
		}

		// Generic LSM BPF needs more complex userspace logic to load, so ignore it
		if strings.HasPrefix(fileName, "bpf_generic_lsm") {
			continue
		}

		// Check if bpf_override_return is available
		if strings.HasPrefix(fileName, "bpf_generic_kprobe") || strings.HasPrefix(fileName, "bpf_enforcer") {
			if err := features.HaveProgramHelper(ebpf.Kprobe, asm.FnOverrideReturn); err != nil {
				continue
			}
		}

		spec, err := ebpf.LoadCollectionSpec(tetragonDir + "/" + fileName)
		require.NoError(t, err, "failed to parse elf file into collection spec")
		require.NotNil(t, spec, "collection spec should not be nil")

		if isDebugEnabled() {
			for _, progSpec := range spec.Programs {
				fmt.Printf("%s\n", progSpec.Instructions.String())
			}
		}

		collection, err := ebpf.NewCollection(spec)
		require.NoError(t, err, "failed to load resources into the kernel")

		collection.Close()
	}
}

func isDebugEnabled() bool {
	debug, err := strconv.ParseBool(os.Getenv("DEBUG"))
	return err == nil && debug
}
