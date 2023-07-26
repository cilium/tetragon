// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package strutils

import "strings"

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
