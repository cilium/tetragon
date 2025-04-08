// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/tetragon/pkg/vmtests"
)

var (
	tetragonDir = "."
	goTestsDir  = filepath.Join(tetragonDir, "go-tests")
	outDir      = filepath.Join(tetragonDir, "tests", "vmtests")
)

func splitProgs(n int, blacklist []vmtests.GoTest) error {
	tests, err := vmtests.ListTests(goTestsDir, false, blacklist)
	if err != nil || len(tests) == 0 {
		return fmt.Errorf("no tests found (err:%w). Is %s accesible? Did you run `make test-compile`?", err, goTestsDir)
	}

	files := make([]*os.File, n)
	for i := range n {
		fname := filepath.Join(outDir, fmt.Sprintf("test-group-%d", i))
		files[i], err = os.Create(fname)
		if err != nil {
			return err
		}
		defer files[i].Close()
	}

	// NB: Some programs take longer than others. We allocate them
	// one-by-one in groups hoping that this will lead to a decent
	// load-balance between the groups.
	i := 0
	for _, test := range tests {
		fmt.Fprintf(files[i%n], "%s\n", test.ToString())
		i++
	}

	return nil
}

var CiBlacklist = []vmtests.GoTest{
	// pkg.exporter has a rate limit test, which is time-dependent. There
	// was a previous attempt to fix the test, but failed. Ignore it for
	// now.
	{PackageProg: "pkg.exporter"},
	// pkg.grpc.exec relies on sleep() calls in order to wait for the
	// eventcache to run. Running them on heavily loaded VM cause flakes.
	// As they are not kernel-dependant, let's run them only as part of
	// gotests.
	{PackageProg: "pkg.grpc.exec"},
}

func usage() {
	fmt.Fprintf(
		flag.CommandLine.Output(),
		"Usage: %s [flags] <ngroups> -- split tests in <ngroups> groups. Output is %s/test-group-X.\n",
		os.Args[0], outDir,
	)
	flag.PrintDefaults()
}

func main() {

	var cirun bool
	flag.BoolVar(&cirun, "ci-run", false, "This option enables CI blacklist for tests")
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(0)
	}

	n, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		usage()
		os.Exit(1)
	}

	var blacklist []vmtests.GoTest
	if cirun {
		blacklist = CiBlacklist
	}
	err = splitProgs(n, blacklist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
