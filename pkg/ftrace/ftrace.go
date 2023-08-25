// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ftrace

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"golang.org/x/exp/slices"
)

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func ReadAvailFuncs(pattern string) ([]string, error) {
	list, err := readLines("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return []string{}, err
	}

	for idx := range list {
		line := list[idx]
		// skip modules
		if strings.ContainsAny(line, " ") {
			list = list[:idx]
			break
		}
	}

	slices.Sort[string](list)
	list = slices.Compact[[]string, string](list)

	var r *regexp.Regexp

	if pattern != "" {
		r, _ = regexp.Compile(pattern)
	}

	final := []string{}

	for idx := range list {
		line := list[idx]
		if strings.Contains(line, "__ftrace_invalid_address__") {
			continue
		}
		if r != nil && !r.MatchString(line) {
			continue
		}
		final = append(final, line)
	}

	return final, nil
}
