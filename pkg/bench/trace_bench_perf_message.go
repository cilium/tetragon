// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bench

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"text/template"

	"github.com/cilium/tetragon/pkg/observer"
)

// Command-line flags
var (
	perfMsgThreads *uint
	perfMsgLoops   *uint
	perfMsgGroups  *uint
	perfMsgData    *bool
)

func init() {
	perfMsgLoops = flag.Uint("bench-perf-loops", 20000, "bench perf number of loops")
	perfMsgGroups = flag.Uint("bench-perf-gorups", 1, "bench perf number of groups")
	perfMsgData = flag.Bool("bench-perf-data", false, "bench perf with data")
}

type traceBenchPerfMsg struct {
}

func (src traceBenchPerfMsg) Run(ctx context.Context, args *Arguments, summary *Summary) error {
	var err error

	// perf is using libbpf.. let it use the good one ;-)
	err = os.Unsetenv("LD_LIBRARY_PATH")
	if err != nil {
		return err
	}

	// run the benchmark
	cmd := exec.Command("perf", "bench", "sched", "messaging", "-t",
		"-l", strconv.Itoa(int(*perfMsgLoops)),
		"-g", strconv.Itoa(int(*perfMsgGroups)))

	fmt.Printf("running: '%s' data(%v)\n", cmd.String(), *perfMsgData)

	// get the result
	var out []byte

	out, err = cmd.Output()
	if err != nil {
		fmt.Printf("%s\n", err)
	}
	fmt.Printf("%s\n", out)
	return nil
}

func (src traceBenchPerfMsg) Crd(ctx context.Context, args *Arguments) string {
	matchPid := strconv.Itoa(int(observer.GetMyPid()))

	var tmpl string

	if *perfMsgData {
		tmpl = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write_writev"
spec:
  kprobes:
  - call: "__x64_sys_write"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "int"
  - call: "__x64_sys_read"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      returnCopy: true
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - {{.MatchPid}}
`
	} else {
		tmpl = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write_writev"
spec:
  kprobes:
  - call: "__x64_sys_write"
    syscall: true
    args:
    - index: 0
      type: "int"
  - call: "__x64_sys_read"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - {{.MatchPid}}
`
	}

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

func newTraceBenchPerfMsg() *traceBenchPerfMsg {
	return &traceBenchPerfMsg{}
}
