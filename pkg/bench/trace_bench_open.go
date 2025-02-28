// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bench

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"
	"time"
)

// Command-line flags
var (
	openLoops   *uint
	openThreads *uint
	openSleep   *uint
)

func init() {
	openSleep = flag.Uint("bench-open-sleep", 1, "bench open sleep between open syscalls (us)")
	openLoops = flag.Uint("bench-open-loops", 1000000, "bench open number of loops")
	openThreads = flag.Uint("bench-open-threads", 4, "bench open number of threads")
}

type traceBenchOpen struct {
}

func (src traceBenchOpen) benchWorker(ctx context.Context) {
	name := "/tmp/non-existing-file"

	var loop uint

	for ctx.Err() == nil {
		var err error

		_, err = syscall.Open(name, 0, 0)
		if err == nil {
			fmt.Printf("failed: open did not fail\n")
			break
		}

		loop++
		if loop == *openLoops {
			break
		}

		if *openSleep != 0 {
			time.Sleep(time.Duration(*openSleep) * time.Microsecond)
		}
	}
}

func (src traceBenchOpen) Run(ctx context.Context, _ *Arguments, _ *Summary) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	fmt.Printf("threads %v, loops %v, sleep %v(us)\n", *openThreads, *openLoops, *openSleep)

	var i uint

	for i = 0; i < *openThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src.benchWorker(ctx)
		}()
	}

	return nil
}

func (src traceBenchOpen) ConfigFilename(_ *Arguments) string {
	tmpl := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write-writev"
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
    - index: 2
      type: "int"
`

	f, err := os.CreateTemp("/tmp", "fgs-bench-hubble-crd-*.yaml")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	f.Write([]byte(tmpl))
	return f.Name()
}

func newTraceBenchOpen() *traceBenchOpen {
	return &traceBenchOpen{}
}
