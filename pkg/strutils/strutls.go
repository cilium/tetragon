// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package strutils

import (
	"fmt"
	"strconv"
	"strings"
)

// UTF8FromBPFBytes transforms bpf (C) strings to valid utf-8 strings
//
// NB(kkourt): strings we get from BPF/kernel are C strings: null-terminated sequence of bytes. They
// may or may not be valid utf-8 strings. This is true for pathnames (cwd, binary) as well as
// program arguments. Many of these fields, however, are represented as the protobuf string type,
// which always has to be utf-8 encoded.
//
// This function ensures that by replacing all invalid runes with '�'.
//
// Note that this approach means that we loose information.
// Alternatively, we could use strconf.Quote() or similar to quote the strings but this would add
// overhead and it will also break the way we 've been representing strings up until now. A better
// solution would be to update the fields in the proto description to be bytes, and let the proto
// clients (e.g., tetra CLI and JSON writer) choose their preffered approach.
func UTF8FromBPFBytes(b []byte) string {
	return strings.ToValidUTF8(string(b), "�")
}

func ParseSize(str string) (int, error) {
	suffix := str[len(str)-1:]

	if !strings.Contains("KMG", suffix) {
		return strconv.Atoi(str)
	}

	val, err := strconv.Atoi(str[0 : len(str)-1])
	if err != nil {
		return 0, err
	}

	switch suffix {
	case "K":
		return val * 1024, nil
	case "M":
		return val * 1024 * 1024, nil
	case "G":
		return val * 1024 * 1024 * 1024, nil
	}

	// never reached
	return 0, nil
}

func SizeWithSuffix(size int) string {
	suffix := [4]string{"", "K", "M", "G"}

	i := 0
	for size > 1024 && i < 3 {
		size = size / 1024
		i++
	}

	return fmt.Sprintf("%d%s", size, suffix[i])
}
