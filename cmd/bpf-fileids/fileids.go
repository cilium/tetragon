// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

/*
typedef struct {
	const char *filename;
	int id;
}  fileid_t;

const fileid_t *get_fileids() {
    static fileid_t fileids[] = {
#define fileid__(f, id)                  { f, id },
#include "../../bpf/tetragon/fileids.h"
#undef fileid__
		{ NULL, -1 }
	};
	return fileids;
}

size_t get_fileids_len() {
    const fileid_t *fileids = get_fileids();
	size_t len = 0;
	while (fileids[len].filename != NULL) {
		len++;
	}
	return len;
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"unsafe"
)

// json entry
type Entry struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
}

func loadFileIDs() []Entry {
	fileidsLen := C.get_fileids_len()
	cArrayPtr := C.get_fileids()
	if cArrayPtr == nil {
		fmt.Fprintf(os.Stderr, "Failed to allocate C array.")
		os.Exit(1)
	}
	goSlice := (*[1 << 30]C.fileid_t)(unsafe.Pointer(cArrayPtr))[:fileidsLen:fileidsLen]
	var ret []Entry
	for _, fileid := range goSlice {
		id := int(fileid.id)
		name := C.GoString(fileid.filename)
		ret = append(ret, Entry{id, name})
	}
	return ret
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <out.json>\n", os.Args[0])
		os.Exit(1)
	}

	fileIDs := loadFileIDs()
	b, err := json.MarshalIndent(fileIDs, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling file ids: %v", err)
		os.Exit(1)
	}

	outFname := os.Args[1]
	err = os.WriteFile(outFname, b, 0622)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing file: %v", err)
		os.Exit(1)
	}
}
