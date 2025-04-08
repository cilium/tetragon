// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package vmtests includes utilities for running tetragon tests inside VMs. It allows the program
// that manages the VM to coordinate with the tester, i.e., program that runs the tests (inside the VM). The
// former will provide a configuration file (TesterConf) to the latter, and the latter will produce
// a set of results (Result[]) to the former (typically, also as a JSON file).
//
// The tester requires access to a tetragon source directory. The way it works for now is
// by using the compiled go tests in the go-tests directory. It them and produces a Result for each
// of them. This can be extended in the future. The configuration file can be used to pass
// specific options for all or individual tests (e.g., timeouts).
package vmtests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	ConfFile     = "/etc/tetragon-tester.json" // configuration file for the tester
	TestTimeout  = 45 * time.Minute            // timeout for each test
	bugtoolFname = "/tmp/tetragon-bugtool.tar.gz"
)

// Conf configures the tester
type Conf struct {
	NoPowerOff  bool   `json:"no-poweroff"`  // do not power-off the machine when done
	TetragonDir string `json:"tetragon-dir"` // tetragon source dir
	ResultsDir  string `json:"results-dir"`  // directory to place the results
	TestsFile   string `json:"tests-file"`   // file describing which tests to run
	BTFFile     string `json:"btf-file"`     // btf file to use
	FailFast    bool   `json:"fail-fast"`
	KeepAllLogs bool   `json:"keep-all-logs"`
	KernelVer   string `json:"kernel-ver"` // kernel version
}

// Result is the result of a single test
type Result struct {
	Name       string        `json:"name"`
	Skip       bool          `json:"skip"`
	Error      bool          `json:"error"`
	Outfile    string        `json:"outfile,omitempty"`
	Duration   time.Duration `json:"duration"`
	BugtoolOut string        `json:"bugtool-out,omitempty"`
}

func copyBugTool(cnf *Conf, res *Result) error {
	in, err := os.Open(bugtoolFname)
	if err != nil {
		return err
	}
	defer in.Close()

	outPattern := fmt.Sprintf("%s-bugtool-*.tar.gz", res.Name)
	out, err := os.CreateTemp(cnf.ResultsDir, outPattern)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	res.BugtoolOut = out.Name()
	return nil
}

func printProgress(f *os.File, done <-chan struct{}) {
	ticker := time.NewTicker(6 * time.Second)
	for i := 1; ; i++ {
		select {
		case <-done:
			return

		case <-ticker.C:
			if i%10 == 0 {
				f.WriteString("m")
			} else {
				f.WriteString(".")
			}
			f.Sync()
		}
	}
}

// Run is the main function that executes the tests based on the configuration.
// Results are written in a results.json file in the results directory, one
// line per result.
// An error is returned only if something unexpected happen and not if the
// tests failed.
func Run(cnf *Conf) error {

	testDir := filepath.Join(cnf.TetragonDir, "go-tests")

	if cnf.BTFFile != "" {
		if err := os.Setenv("TETRAGON_BTF", cnf.BTFFile); err != nil {
			return fmt.Errorf("failed to set TETRAGON_BTF to %s", cnf.BTFFile)
		}
	}

	var tests []GoTest
	if cnf.TestsFile == "" {
		var err error
		tests, err = ListTests(testDir, false, nil)
		if err != nil {
			return err
		}
	} else {
		var err error
		testFile := cnf.TestsFile
		// NB: assume relative dirs are in tetragon dir
		if testFile[0] != '/' {
			testFile = filepath.Join(cnf.TetragonDir, testFile)
		}
		tests, err = LoadTestsFromFile(testDir, testFile)
		if err != nil {
			return err
		}
	}

	resultsFname := filepath.Join(cnf.ResultsDir, "results.json")
	f, err := os.Create(resultsFname)
	if err != nil {
		return err
	}
	defer gatherExportFiles(cnf)

	// helper function to run test and append result to the results file
	doRunTest := func(testName string, cmd string, args ...string) (*Result, error) {
		os.Remove(bugtoolFname)
		res, err := runTest(cnf, testName, cmd, args...)
		if err != nil {
			return nil, err
		}
		if res.Error {
			copyBugTool(cnf, res)
		}

		if b, err := json.Marshal(res); err != nil {
			return res, err
		} else if _, err := f.Write(b); err != nil {
			return res, err
		}

		return res, nil
	}

	for _, test := range tests {
		name := test.PackageProg
		prog := filepath.Join(testDir, name)
		progArgs := []string{"-test.v"}
		if test.Test != "" {
			name = fmt.Sprintf("%s.%s", name, test.Test)
			// It is possible that a test is a substring of another. Use a strict
			// pattern so that we execute only the specified test.
			t := fmt.Sprintf("^%s$", test.Test)
			progArgs = append(progArgs, "-test.run", t)
		}

		if res, err := doRunTest(name, prog, progArgs...); err != nil {
			return err
		} else if cnf.FailFast && res.Error {
			break
		}
	}

	return nil
}

// gather log files created by pkg/testutils/filenames:CreateExportFile()
func gatherExportFiles(cnf *Conf) error {
	err := filepath.Walk("/tmp", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		if !strings.HasPrefix(base, "tetragon.gotest") {
			return nil
		}

		in, err := os.Open(path)
		if err != nil {
			fmt.Printf("failed to open %s. Continuing...\n", path)
			return nil
		}
		defer in.Close()

		outName := filepath.Join(cnf.ResultsDir, base)
		out, err := os.Create(outName)
		if err != nil {
			fmt.Printf("failed to create %s. Continuing...\n", outName)
			return nil
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		if err != nil {
			fmt.Printf("failed to copy %s to %s. Continuing...\n", path, outName)
		}
		return nil
	})
	return err
}

func runTest(cnf *Conf, testName string, cmd string, args ...string) (*Result, error) {

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	if shouldSkip(cnf, testName) {
		fmt.Printf("Skipping test %s ", testName)
		return &Result{
			Name: testName,
			Skip: true,
		}, nil
	}

	fmt.Printf("Running test %s ", testName)
	testCmd := exec.CommandContext(ctx, cmd, args...)

	// create file for output
	outF, err := os.CreateTemp(cnf.ResultsDir, fmt.Sprintf("%s.", testName))
	if err != nil {
		return nil, err
	}
	outFname := outF.Name()
	defer outF.Close()

	// simple progress bar
	done := make(chan struct{})
	go printProgress(os.Stdout, done)

	testCmd.Stdout = outF
	testCmd.Stderr = outF
	t0 := time.Now()
	testErr := testCmd.Run()
	elapsed := time.Since(t0)
	close(done)
	if testErr != nil {
		fmt.Printf("> failed after %s: %v\n", elapsed, testErr)
	} else {
		fmt.Printf("> succeeded after %s\n", elapsed)
		if !cnf.KeepAllLogs {
			if err := os.Remove(outFname); err == nil {
				outFname = ""
			}
		}
	}

	res := Result{
		Name:     testName,
		Error:    testErr != nil,
		Outfile:  outFname,
		Duration: elapsed,
	}

	return &res, nil
}
