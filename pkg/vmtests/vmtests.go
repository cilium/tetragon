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
	ConfFile    = "/etc/tetragon-tester.json" // configuration file for the tester
	TestTimeout = 45 * time.Minute            // timeout for each test
)

// Conf configures the tester
type Conf struct {
	NoPowerOff  bool   `json:"no-poweroff"`  // do not power-off the machine when done
	TetragonDir string `json:"tetragon-dir"` // tetragon source dir
	ResultsDir  string `json:"results-dir"`  // directory to place the results
}

// Result is the result of a single test
type Result struct {
	Name     string        `json:"name"`
	Error    bool          `json:"error"`
	Outfile  string        `json:"outfile"`
	Duration time.Duration `json:"duration"`
}

func printProgress(f *os.File, done <-chan struct{}) {
	for i := 1; ; i++ {
		select {
		case <-done:
			return

		case <-time.After(6 * time.Second):
			if i%10 == 0 {
				f.Write([]byte("m"))
			} else {
				f.Write([]byte("."))
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

	resultsFname := filepath.Join(cnf.ResultsDir, "results.json")
	f, err := os.Create(resultsFname)
	if err != nil {
		return err
	}

	testDir := filepath.Join(cnf.TetragonDir, "go-tests")
	tests, err := ListTests(testDir, false)
	if err != nil {
		return nil
	}

	defer gatherExportFiles(cnf)

	// helper function to run test and append result to the results file
	doRunTest := func(testName string, cmd string, args ...string) error {
		res, err := runTest(cnf, testName, cmd, args...)
		if err != nil {
			return err
		}
		if b, err := json.Marshal(res); err != nil {
			return err
		} else if _, err := f.Write(b); err != nil {
			return err
		}
		return nil
	}

	for _, test := range tests {
		name := test.PackageProg
		prog := filepath.Join(testDir, name)
		progArgs := []string{"-test.v"}
		if test.Test != "" {
			t := test.Test
			name = fmt.Sprintf("%s.%s", name, t)
			progArgs = append(progArgs, "-test.run", t)
		}

		if err := doRunTest(name, prog, progArgs...); err != nil {
			return err
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

		if !strings.HasPrefix(path, "tetragon.gotest.") {
			return nil
		}

		fname := filepath.Join("/tmp", path)
		in, err := os.Open(fname)
		if err != nil {
			fmt.Printf("failed to open %s. Continuing...\n", fname)
			return nil
		}
		defer in.Close()

		outName := filepath.Join(cnf.ResultsDir, path)
		out, err := os.Create(outName)
		if err != nil {
			fmt.Printf("failed to create %s. Continuing...\n", outName)
			return nil
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		if err != nil {
			fmt.Printf("failed to copy %s to %s. Continuing...\n", fname, outName)
		}
		return nil
	})
	return err
}

func runTest(cnf *Conf, testName string, cmd string, args ...string) (*Result, error) {
	fmt.Printf("Running test %s ", testName)

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

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
		if err := os.Remove(outFname); err == nil {
			outFname = ""
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
