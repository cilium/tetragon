// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/isovalent/tetragon-oss/api/v1/fgs"
	ec "github.com/isovalent/tetragon-oss/pkg/eventchecker"
	"github.com/isovalent/tetragon-oss/pkg/testutils"
)

var (
	retryDelay = 2 * time.Second
)

func JsonCheck(jsonFile *os.File, checker ec.MultiResponseChecker, log ec.Logger) error {
	count := 0
	dec := json.NewDecoder(jsonFile)
	for dec.More() {
		var ev fgs.GetEventsResponse
		if err := dec.Decode(&ev); err != nil {
			return fmt.Errorf("unmarshal failed: %w", err)
		}
		count++
		prefix := fmt.Sprintf("jsonTestCheck/line:%04d ", count)
		done, err := checker.NextCheck(&ev, &ec.PrefixLogger{Prefix: prefix, Logger: log})
		prefix = fmt.Sprintf("%sevent:%s", prefix, ec.EventTypeString(ev.Event))
		if done && err == nil {
			log.Logf("%s =>  FINAL MATCH ", prefix)
			log.Logf("jsonTestCheck: DONE!")
			return nil
		} else if err == nil {
			log.Logf("%s => MATCH, continuing", prefix)
		} else if done && err != nil {
			log.Logf("%s => terminating error: %s", prefix, err)
			return err
		} else {
			if _, ok := err.(ec.EventTypeError); !ok {
				log.Logf("%s => no match: %s, continuing", prefix, err)
			}
		}
	}

	if err := checker.FinalCheck(log); err != nil {
		return fmt.Errorf("jsonTestCheck: failed to match after %d events: %w", count, err)
	}
	return nil
}

func JsonTestCheck(t *testing.T, c ec.MultiResponseChecker) error {
	var err error

	jsonFname := testutils.GetExportFilename(t)

	// cleanup function: if test fails, mark export file to be kept
	defer func() {
		if err != nil {
			t.Log("test failed, marking export file to be kept")
			testutils.KeepExportFile(t)
		}
	}()

	// attempt to open the export file
	t.Logf("jsonTestCheck: openning: %s\n", jsonFname)
	jsonFile, err := os.Open(jsonFname)
	if err != nil {
		return fmt.Errorf("opening json file failed: %w", err)
	}
	t.Cleanup(func() { jsonFile.Close() })

	cnt := 0
	for {
		err = JsonCheck(jsonFile, c, t)
		if err == nil {
			break
		}

		cnt++
		if cnt == jsonRetries {
			err = fmt.Errorf("JsonTestCheck failed after %d retries: %w", jsonRetries, err)
			break
		}
		t.Logf("JsonCheck (retry=%d) failed: %s. Retrying after %s", cnt, err, retryDelay)
		jsonFile.Seek(0, io.SeekStart)
		time.Sleep(retryDelay)
		c.Reset()
	}

	return err
}
