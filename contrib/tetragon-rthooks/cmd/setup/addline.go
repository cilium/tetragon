// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/pelletier/go-toml"
)

// special line number to append at the end of the file
const appendAtEndLine = -10

type addLine struct {
	pos         toml.Position
	line        string
	replaceLine bool
}

func applyChanges(fnameIn, fnameOut string, changes []addLine) error {
	fIn, err := os.Open(fnameIn)
	if err != nil {
		return err
	}
	defer fIn.Close()
	cr := "\n"
	if usesCR(fIn) {
		cr = "\r\n"
	}

	fOut, err := os.Create(fnameOut)
	if err != nil {
		return err
	}
	defer fOut.Close()

	inLine := 0
	inSc := bufio.NewScanner(fIn)
	out := bufio.NewWriter(fOut)
	defer out.Flush()
	for inSc.Scan() {
		inLine++
		lines := []string{}
		replaceLine := false
		for i := range changes {
			ch := &changes[i]
			if ch.pos.Line == inLine {
				// NB: we assume that everything before is indentation
				line := strings.Repeat(" ", ch.pos.Col-1) + ch.line + cr
				lines = append(lines, line)
				if ch.replaceLine {
					replaceLine = true
				}
			}
		}
		if !replaceLine {
			out.WriteString(inSc.Text())
			out.WriteString(cr)
		}
		for _, line := range lines {
			out.WriteString(line)
		}
	}

	for i := range changes {
		ch := &changes[i]
		if ch.pos.Line == appendAtEndLine {
			indent := ""
			if ch.pos.Col > 0 {
				indent = strings.Repeat(" ", ch.pos.Col-1)
			}
			line := indent + ch.line + cr
			out.WriteString(line)
		}
	}

	return nil
}
