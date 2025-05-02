// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

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

func (t *GoTest) ToPattern() string {
	if t.Test == "" {
		return t.PackageProg
	}
	// some tests are substrings of others. Use an exact pattern to avoid running tests twice.
	return fmt.Sprintf("%s:^%s$", t.PackageProg, t.Test)
}

func fromString(testDir, s string) []GoTest {

	sl := strings.SplitN(s, ":", 2)
	prog := sl[0]
	if len(sl) < 2 {
		return []GoTest{{PackageProg: prog}}
	}

	pattern := sl[1]
	tests, err := listTests(testDir, prog, pattern)
	if err != nil {
		// NB: we failed to list the tests of a package. Just append the prog.
		return []GoTest{{PackageProg: prog}}
	}

	ret := []GoTest{}
	for _, test := range tests {
		t := GoTest{PackageProg: prog, Test: test}
		ret = append(ret, t)
	}

	return ret
}

func LoadTestsFromFile(testDir string, fname string) ([]GoTest, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var ret []GoTest
	for scanner.Scan() {
		txt := scanner.Text()
		if strings.HasPrefix(txt, "#") {
			continue
		}
		ret = append(ret, fromString(testDir, txt)...)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}

func ListTests(
	testDir string,
	packagesOnly bool,
	blacklist []GoTest,
) ([]GoTest, error) {

	progs, err := listTestProgs(testDir, blacklist)
	if err != nil {
		return nil, err
	}

	blacklistMap := make(map[GoTest]struct{})
	for _, b := range blacklist {
		if b.Test == "" {
			continue
		}
		blacklistMap[b] = struct{}{}
	}

	ret := []GoTest{}
	for _, prog := range progs {
		if packagesOnly {
			ret = append(ret, GoTest{PackageProg: prog})
			continue
		}

		tests, err := listTests(testDir, prog, ".")
		if err != nil {
			// NB: we failed to list the tests of a package. Just append the prog.
			ret = append(ret, GoTest{PackageProg: prog})
			continue
		}

		for _, test := range tests {
			t := GoTest{PackageProg: prog, Test: test}
			if _, ok := blacklistMap[t]; ok {
				continue
			}
			ret = append(ret, t)
		}
	}

	return ret, nil
}

// listTestProgs lists tests programs from the filesystem (typically, this is the go-tests directory)
func listTestProgs(testDir string, blacklist []GoTest) ([]string, error) {
	files, err := os.ReadDir(testDir)
	if err != nil {
		return nil, err
	}

	blackListedPackages := make(map[string]struct{})
	for _, t := range blacklist {
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

// listTests list the test of a test program by passing "-test.list <pattern>" to it.
func listTests(testDir string, testProg string, testPattern string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Callers should use ".", but as a sanity check if pattern is empty, we set the pattern to
	// "."
	if testPattern == "" {
		testPattern = "."
	}

	prog := filepath.Join(testDir, testProg)
	listCmd := exec.CommandContext(ctx, prog, "-test.list", testPattern)
	out, err := listCmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

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
