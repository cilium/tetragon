// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errmetrics

import (
	_ "embed"
	"encoding/json"
	"log"
)

var (
	MapName = "errmetrics_map"
)

// json entry
type Entry struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
}

//go:embed fileids.json
var fileIDsJSON []byte

func initFileIDs() map[int]string {
	var entries []Entry
	if err := json.Unmarshal(fileIDsJSON, &entries); err != nil {
		log.Panic(err)
		return nil
	}

	ret := map[int]string{}
	for _, e := range entries {
		ret[e.ID] = e.Filename
	}
	return ret
}

var fileIDs = initFileIDs()
