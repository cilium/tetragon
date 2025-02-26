// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bench

import (
	"context"
	"flag"
	"log"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"text/template"
	"time"

	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
)

// Command-line flags
var (
	rwLoops   *uint
	rwSize    *uint
	rwCount   *uint
	rwThreads *uint
	rwSleep   *uint
	rwRandom  *bool
)

func init() {
	rwLoops = flag.Uint("bench-rw-loops", 100, "bench rw number of loops")
	rwSize = flag.Uint("bench-rw-size", 1024, "bench rw buffer size")
	rwCount = flag.Uint("bench-rw-count", 100, "bench rw read/write count")
	rwThreads = flag.Uint("bench-rw-threads", 4, "bench rw number of threads")
	rwSleep = flag.Uint("bench-rw-sleep", 1, "bench rw sleep in ms")
	rwRandom = flag.Bool("bench-rw-random", false, "use random rw size")
}

type traceBenchRw struct {
}

func (src traceBenchRw) benchRwWorker(ctx context.Context) {
	f, err := os.CreateTemp("/tmp", "fgs-bench-hubble-crd-*.data")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())

	var loop uint
	var syscall uint

	buffer := make([]byte, *rwSize)

	size := func() uint {
		if *rwRandom {
			return uint(rand.Intn(int(*rwSize)-1) + 1)
		}
		return *rwSize
	}

	for ctx.Err() == nil {
		syscall = 0

		for {
			n, errno := f.Write(buffer[:size()])
			if n < 0 {
				log.Fatalf("syscall.Write failed: %s\n", errno)
			}

			// give us a chance to catch up
			time.Sleep(time.Duration(*rwSleep) * time.Microsecond)

			syscall++
			if syscall == *rwCount {
				break
			}
		}

		f.Seek(0, 0)
		syscall = 0

		for {
			n, errno := f.Read(buffer[:size()])
			if n < 0 {
				log.Fatalf("syscall.Read failed: %s\n", errno)
			}

			// give us a chance to catch up
			time.Sleep(time.Duration(*rwSleep) * time.Microsecond)

			syscall++
			if syscall == *rwCount {
				break
			}
		}

		loop++
		if loop == *rwLoops {
			break
		}
	}
}

func (src traceBenchRw) Run(ctx context.Context, _ *Arguments, _ *Summary) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	var i uint

	for i = 0; i < *rwThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src.benchRwWorker(ctx)
		}()
	}

	return nil
}

func (src traceBenchRw) ConfigFilename(_ *Arguments) string {
	matchPid := strconv.Itoa(int(observertesthelper.GetMyPid()))

	tmpl := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write-writev"
spec:
  kprobes:
  - call: "sys_write"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "int"
  - call: "sys_read"
    syscall: true
    return: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      returnCopy: true
    - index: 2
      type: "size_t"
    returnArg:
      index: 0
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - {{.MatchPid}}
`

	f, err := os.CreateTemp("/tmp", "fgs-bench-hubble-crd-*.yaml")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	templateArgs :=
		struct {
			MatchPid string
		}{
			MatchPid: matchPid,
		}

	err = template.Must(template.New("crd").Parse(tmpl)).Execute(f, templateArgs)
	if err != nil {
		log.Fatal(err)
	}
	return f.Name()
}

func newTraceBenchRw() *traceBenchRw {
	return &traceBenchRw{}
}
