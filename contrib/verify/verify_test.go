// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package verify

import (
	"flag"
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
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	TETRAGONDIR = "/var/lib/tetragon"
)

var (
	DEBUG = flag.Bool("d", false, "debug")
)

func TestVerifyTetragonPrograms(t *testing.T) {

	kernelVersion, err := strconv.ParseFloat(getKernelVersion(), 64)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	tetragonDir := os.Getenv("TETRAGONDIR")
	if tetragonDir == "" {
		tetragonDir = TETRAGONDIR
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
		if strings.HasSuffix(fileName, "61.o") && kernelVersion < 6.1 {
			continue
		}

		// Skip v5.11 objects check for kernel < 5.11
		if strings.HasSuffix(fileName, "511.o") && kernelVersion < 5.11 {
			continue
		}

		// Skip bpf_loader for kernel < 5.19
		if strings.HasPrefix(fileName, "bpf_loader") && kernelVersion < 5.19 {
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

		if *DEBUG {
			for _, progSpec := range spec.Programs {
				fmt.Printf("%s\n", progSpec.Instructions.String())
			}
		}

		coll, err := ebpf.NewCollection(spec)
		require.NoError(t, err, "failed to load resources into the kernel")

		defer coll.Close()

		for _, prog := range coll.Programs {
			require.NotEqual(t, -1, prog.FD())
			prog.Close()
		}
	}

}

func getKernelVersion() string {
	var uts unix.Utsname
	err := unix.Uname(&uts)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	var release []byte
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}

	version := strings.Split(string(release), ".")
	if len(version) < 2 {
		log.Fatalf("error: unexpected kernel version format")
	}

	return strings.Join(version[:2], ".")
}
