// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/cilium/tetragon/pkg/vmtests"
	"golang.org/x/sys/unix"
)

type runTestsResults struct {
	nrTests, nrFailedTests, nrSkipedTests int
}

func runTests(
	rcnf *RunConf, qemuBin string, qemuArgs []string,
) (*runTestsResults, error) {

	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, unix.SIGINT, unix.SIGTERM)
	defer cancel()
	qemuCmd := exec.CommandContext(ctx, qemuBin, qemuArgs...)

	// buffer output from qemu's  stdout/stderr to avoid delays
	bout := bufio.NewWriter(os.Stdout)
	berr := bufio.NewWriter(os.Stderr)
	qemuCmd.Stdout = bout
	qemuCmd.Stderr = berr
	if err := qemuCmd.Run(); err != nil {
		return nil, err
	}
	bout.Flush()
	berr.Flush()

	fmt.Printf("results directory: %s\n", rcnf.testerConf.ResultsDir)
	resFile := filepath.Join(rcnf.testerConf.ResultsDir, "results.json")

	f, err := os.Open(resFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open results file %s: %v", resFile, err)
	}
	defer f.Close()

	var results []vmtests.Result
	decoder := json.NewDecoder(f)
	for {
		var result vmtests.Result
		if err := decoder.Decode(&result); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("JSON decoding failed: %w", err)
		}

		results = append(results, result)
	}

	var totalDuration time.Duration
	errCnt := 0
	skipCnt := 0
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	for _, r := range results {
		totalDuration += r.Duration
		ok := "✅"
		if r.Error {
			ok = "❌"
			errCnt++
		} else if r.Skip {
			ok = "⏭️"
			skipCnt++
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t(%s)\n", ok, r.Name, r.Duration.Round(time.Millisecond), totalDuration.Round(time.Millisecond))
	}
	w.Flush()

	return &runTestsResults{
		nrTests:       len(results),
		nrFailedTests: errCnt,
		nrSkipedTests: skipCnt,
	}, nil
}
