// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// json entry
type Entry struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
}

func initFileIDs(fname string) []Entry {
	entryRe := regexp.MustCompile(`fileid__\("([^"]+)", *([0-9]+)\)`)
	f, err := os.Open(fname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening '%s': %v", fname, err)
		os.Exit(1)
	}
	defer f.Close()

	ret := []Entry{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "//") {
			continue
		}

		m := entryRe.FindStringSubmatch(line)
		if len(m) == 3 {
			id, err := strconv.ParseInt(m[2], 0, 32)
			if err != nil {
				continue
			}
			ret = append(ret, Entry{int(id), m[1]})
		}

	}
	// NB: no need to check scanner.Err()
	return ret
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <fileids.h> <out.json>\n", os.Args[0])
		os.Exit(1)
	}

	fname := os.Args[1]
	fileIDs := initFileIDs(fname)
	b, err := json.MarshalIndent(fileIDs, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling file ids: %v", err)
		os.Exit(1)
	}

	outFname := os.Args[2]
	err = os.WriteFile(outFname, b, 0622)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing file: %v", err)
		os.Exit(1)
	}
}
