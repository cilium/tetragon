// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package jsonchecker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/sirupsen/logrus"
)

var (
	Retries    = 20
	RetryDelay = 2 * time.Second
)

// DebugError is an error that will create a debug output message
type DebugError struct {
	err error
}

func NewDebugError(err error) *DebugError {
	if err == nil {
		return nil
	}
	return &DebugError{
		err: err,
	}
}

// Error returns the error message
func (e *DebugError) Error() string {
	return fmt.Sprintf("DebugError: %v", e.err)
}

// Unwrap returns the original error
func (e *DebugError) Unwrap() error {
	return e.err
}

// JsonEOF is a type of error where we went over all the events and there was no match.
//
// The reason to have a special error is that there are cases where the events
// we are looking for might not have been processed yet. In these cases, we
// need to retry.
type JsonEOF struct {
	// err is what FinalCheck() returned
	err error
	// count is the number of events we checked
	count int
}

// Error returns the error message
func (e *JsonEOF) Error() string {
	return fmt.Sprintf("JsonEOF: failed to match after %d events: err:%v", e.count, e.err)
}

// Unwrap returns the original error
func (e *JsonEOF) Unwrap() error {
	return e.err
}

// JsonCheck checks a JSON string using the new eventchecker library.
func JsonCheck(jsonFile *os.File, checker ec.MultiEventChecker, log *logrus.Logger) error {
	count := 0
	dec := json.NewDecoder(jsonFile)
	for dec.More() {
		var dbgErr *DebugError
		var ev tetragon.GetEventsResponse
		if err := dec.Decode(&ev); err != nil {
			return fmt.Errorf("unmarshal failed: %w", err)
		}
		count++
		prefix := fmt.Sprintf("jsonTestCheck/line:%04d ", count)
		eType, err := helpers.ResponseTypeString(&ev)
		if err != nil {
			eType = "<UNKNOWN>"
		}
		matchPrefix := fmt.Sprintf("%sevent:%s", prefix, eType)
		done, err := ec.NextResponseCheck(checker, &ev, log)
		if done && err == nil {
			log.Infof("%s =>  FINAL MATCH", matchPrefix)
			log.Infof("jsonTestCheck: DONE!")
			return nil
		} else if err == nil {
			log.Infof("%s => MATCH, continuing", matchPrefix)
		} else if done && err != nil {
			log.Errorf("%s => terminating error: %s", matchPrefix, err)
			return err
		} else if errors.As(err, &dbgErr) {
			log.Debugf("%s => no match: %s, continuing", matchPrefix, err)
		} else {
			log.Infof("%s => no match: %s, continuing", matchPrefix, err)
		}
	}

	if err := checker.FinalCheck(log); err != nil {
		return &JsonEOF{
			count: count,
			err:   err,
		}
	}
	return nil
}

// JsonTestCheck checks a JSON file using the new eventchecker library.
func JsonTestCheck(t *testing.T, checker ec.MultiEventChecker) error {
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
	t.Logf("jsonTestCheck: opening: %s\n", jsonFname)
	jsonFile, err := os.Open(jsonFname)
	if err != nil {
		return fmt.Errorf("opening json file failed: %w", err)
	}
	t.Cleanup(func() { jsonFile.Close() })

	fieldLogger := logger.GetLogger()
	log, ok := fieldLogger.(*logrus.Logger)
	if !ok {
		return fmt.Errorf("failed to convert logger")
	}
	defer captureLog(t).Release()

	cnt := 0
	for {
		err = JsonCheck(jsonFile, checker, log)
		if err == nil {
			break
		}

		// if this is not a JsonEOF error, it means that the checker
		// concluded that there was a falure. Dont retry.
		var errEOF *JsonEOF
		if !errors.As(err, &errEOF) {
			break
		}

		cnt++
		if cnt > Retries {
			err = fmt.Errorf("JsonTestCheck failed after %d retries: %w", Retries, err)
			break
		}
		t.Logf("JsonCheck (retry=%d) failed: %s. Retrying after %s", cnt, err, RetryDelay)
		jsonFile.Seek(0, io.SeekStart)
		time.Sleep(RetryDelay)
	}

	return err
}
