// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errmetrics

import (
	_ "embed"
	"encoding/json"
	"sync"
)

var (
	MapName = "tg_errmetrics_map"
)

// json entry
type Entry struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
}

//go:embed fileids.json
var fileIDsJSON []byte

var getFileIDs = sync.OnceValues(func() (map[int]string, error) {
	var entries []Entry
	if err := json.Unmarshal(fileIDsJSON, &entries); err != nil {
		return nil, err
	}

	ret := map[int]string{}
	for _, e := range entries {
		ret[e.ID] = e.Filename
	}
	return ret, nil
})
