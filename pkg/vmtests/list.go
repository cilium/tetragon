package vmtests

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GoTest is a PackageProg and a Test name. If Test is "", then running all the package is implied
type GoTest struct {
	PackageProg, Test string
}

func (t *GoTest) ToString() string {
	if t.Test == "" {
		return t.PackageProg
	}
	return fmt.Sprintf("%s:%s", t.PackageProg, t.Test)
}

// NB: hardcoded, for now. Eventually, we might expose user knobs for it
var Blacklist = []GoTest{
	// pkg.exporter has a rate limit test, which is time-dependent. There
	// was a previous attempt to fix the test, but failed. Ignore it for
	// now.
	{PackageProg: "pkg.exporter"},
}

func ListTests(testDir string, packagesOnly bool) ([]GoTest, error) {

	progs, err := listTestProgs(testDir)
	if err != nil {
		return nil, err
	}

	ret := []GoTest{}
	for _, prog := range progs {
		if packagesOnly {
			ret = append(ret, GoTest{PackageProg: prog})
			continue
		}

		tests, err := listTests(testDir, prog)
		if err != nil {
			// NB: we failed to list the tests of a package. Just append the prog.
			ret = append(ret, GoTest{PackageProg: prog})
			continue
		}

		for _, test := range tests {
			ret = append(ret, GoTest{
				PackageProg: prog,
				Test:        test,
			})
		}
	}

	return ret, nil
}

// listTestProgs lists tests programs from the filesystem (typically, this is the go-tests directory)
// It filters the programs based on Blacklist.
func listTestProgs(testDir string) ([]string, error) {
	files, err := os.ReadDir(testDir)
	if err != nil {
		return nil, err
	}

	blackListedPackages := make(map[string]struct{})
	for _, t := range Blacklist {
		if t.Test == "" {
			blackListedPackages[t.PackageProg] = struct{}{}
		}
	}

	var ret []string
	// for now, we have a single top-level directory
	for _, entry := range files {
		name := entry.Name()
		// NB: for now, consider only tests from packages. This ignores e2e tests found in
		// tests/e2e/tests/.
		if !strings.HasPrefix(name, "pkg.") {
			continue
		}
		if _, ok := blackListedPackages[name]; ok {
			continue
		}
		ret = append(ret, name)
	}

	return ret, nil
}

// listTests list the test of a test program by passing "-test.list ." to it.
func listTests(testDir string, testProg string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prog := filepath.Join(testDir, testProg)
	listCmd := exec.CommandContext(ctx, prog, "-test.list", ".")
	out, err := listCmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// TODO: blacklist: get the tests have this package as a prefix, and skip them.

	var ret []string
	reader := bytes.NewReader(out)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		txt := scanner.Text()
		if !strings.HasPrefix(txt, "Test") {
			// fmt.Printf("skipping %s\n", txt)
			continue
		}
		ret = append(ret, txt)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}
