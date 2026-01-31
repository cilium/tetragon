// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// synthetic-roundtrip reads events from a JSONL file, unmarshals them,
// marshals back, and compares the results to verify roundtrip correctness.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/cilium/tetragon/pkg/synthetic"
)

func main() {
	inputFile := flag.String("input", "synthetic-events.jsonl", "Input JSONL file")
	outputFile := flag.String("output", "", "Output JSONL file (optional, for comparison)")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if err := run(*inputFile, *outputFile, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(inputFile, outputFile string, verbose bool) error {
	f, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer f.Close()

	var outFile *os.File
	if outputFile != "" {
		outFile, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer outFile.Close()
	}

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var (
		lineNum    int
		success    int
		failures   int
		mismatches int
	)

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		if len(line) == 0 {
			continue
		}

		// Step 1: Unmarshal
		codec := synthetic.Serializer{}
		event, err := codec.Unmarshal(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Line %d: Unmarshal failed: %v\n", lineNum, err)
			failures++
			continue
		}

		// Step 2: Marshal back
		remarshaled, err := codec.Marshal(event)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Line %d: MarshalEvent failed: %v\n", lineNum, err)
			failures++
			continue
		}

		// Write to output if specified
		if outFile != nil {
			outFile.Write(remarshaled)
			outFile.WriteString("\n")
		}

		// Step 3: Compare
		if !bytes.Equal(line, remarshaled) {
			mismatches++
			if verbose {
				fmt.Fprintf(os.Stderr, "Line %d: mismatch\n", lineNum)
				fmt.Fprintf(os.Stderr, "  Original:    %s\n", string(line))
				fmt.Fprintf(os.Stderr, "  Remarshaled: %s\n", string(remarshaled))
			}
		} else {
			success++
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	fmt.Printf("Results:\n")
	fmt.Printf("  Total lines:  %d\n", lineNum)
	fmt.Printf("  Success:      %d\n", success)
	fmt.Printf("  Failures:     %d\n", failures)
	fmt.Printf("  Mismatches:   %d\n", mismatches)

	if failures > 0 || mismatches > 0 {
		return fmt.Errorf("roundtrip test failed")
	}

	fmt.Println("\n✓ All events roundtrip correctly!")
	return nil
}
