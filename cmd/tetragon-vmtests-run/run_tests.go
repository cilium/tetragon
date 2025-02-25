// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"bufio"
	"bytes"
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
	totalDuration                         time.Duration
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

	var out runTestsResults
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	for _, res := range results {
		// NB: res.Skip means that the test was never executed, so we cannot print detailed
		// results.
		if rcnf.detailedResults && res.Outfile != "" && !res.Skip {
			updateResultsDetailed(w, &res, &out)
		} else {
			updateResultsSimple(w, &res, &out)
		}
	}
	w.Flush()

	return &out, nil
}

func updateResultsSimple(w io.Writer, res *vmtests.Result, out *runTestsResults) {
	out.nrTests++
	out.totalDuration += res.Duration
	ok := "✅"
	if res.Error {
		ok = "❌"
		out.nrFailedTests++
	} else if res.Skip {
		// "⏭️"
		// ok = "\u23E9"
		out.nrSkipedTests++
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t(%s)\n", ok, res.Name, res.Duration.Round(time.Millisecond), out.totalDuration.Round(time.Millisecond))
}

// see: https://pkg.go.dev/cmd/test2json
type TestEvent struct {
	Time    time.Time // encodes as an RFC3339-format string
	Action  string
	Package string
	Test    string
	Elapsed float64 // seconds
	Output  string
}

func updateResultsDetailed(w io.Writer, res *vmtests.Result, out *runTestsResults) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f, err := os.Open(res.Outfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error openning %s: %v", res.Outfile, res)
		updateResultsSimple(w, res, out)
		return
	}
	defer f.Close()

	prog := "go"
	// NB: we need -t to enable timestamps and get the Elapsed field
	args := []string{"tool", "test2json", "-t"}
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Stdin = f
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing test2json: %v", res)
		updateResultsSimple(w, res, out)
		return
	}
	buff := bytes.NewBuffer(output)
	scanner := bufio.NewScanner(buff)

	var totalDuration time.Duration

	type detail struct {
		name string
		icon string
		dur  time.Duration
	}
	var details []detail

	nrTests := 0
	nrSkippedTests := 0
	nrFailedTests := 0
	for scanner.Scan() {
		var tevent TestEvent
		line := scanner.Bytes()
		err := json.Unmarshal(line, &tevent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing: '%s': %v, bailing out", line, err)
			updateResultsSimple(w, res, out)
			return
		}
		if tevent.Test == "" {
			continue
		}

		var icon string
		switch tevent.Action {
		case "skip":
			nrSkippedTests++
			// "⚡"
			icon = "\u26a1"
		case "pass":
			icon = "✅"
		case "fail":
			nrFailedTests++
			icon = "❌"
		default:
			continue
		}

		nrTests++
		dur := time.Duration(float64(time.Second) * tevent.Elapsed)
		details = append(details, detail{name: tevent.Test, icon: icon, dur: dur})

	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Scanner failed: %v, bailing out", err)
		updateResultsSimple(w, res, out)
		return
	}

	out.totalDuration += res.Duration
	out.nrTests += nrTests
	out.nrSkipedTests += nrSkippedTests
	out.nrFailedTests += nrFailedTests

	icon := "✅"
	if res.Error {
		icon = "❌"
	} else if nrSkippedTests == nrTests {
		// "⚡"
		icon = "\u26a1"
	} else if nrFailedTests > 0 {
		// NB(kkourt): res.Error should not be false
		icon = "⁉️"
	}

	fmt.Fprintf(w, "%s\t%s\t(total:%d failed:%d skipped:%d)\t%s\t%s\n", icon, res.Name, nrTests, nrFailedTests, nrSkippedTests, res.Duration, out.totalDuration)
	if len(details) > 1 {
		for i, detail := range details {
			totalDuration += detail.dur
			if i == len(details)-1 {
				fmt.Fprintf(w, "└─%s\t%s\t%s\t(%s)\n", detail.icon, detail.name, detail.dur.Round(time.Millisecond), totalDuration)
			} else {
				fmt.Fprintf(w, "├─%s\t%s\t%s\t(%s)\n", detail.icon, detail.name, detail.dur.Round(time.Millisecond), totalDuration)
			}
		}
	}

}
