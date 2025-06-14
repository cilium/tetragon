// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package jsonchecker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/testutils"
)

var (
	Retries    = 13
	RetryDelay = 3 * time.Second
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

// JsonEOFError is a type of error where we went over all the events and there was no match.
//
// The reason to have a special error is that there are cases where the events
// we are looking for might not have been processed yet. In these cases, we
// need to retry.
type JsonEOFError struct {
	// err is what FinalCheck() returned
	err error
	// count is the number of events we checked
	count int
}

// Error returns the error message
func (e *JsonEOFError) Error() string {
	return fmt.Sprintf("JsonEOF: failed to match after %d events: err:%v", e.count, e.err)
}

// Unwrap returns the original error
func (e *JsonEOFError) Unwrap() error {
	return e.err
}

// JsonCheck checks a JSON string using the new eventchecker library.
func JsonCheck(jsonFile *os.File, checker ec.MultiEventChecker, log *slog.Logger) error {
	count := 0
	dec := json.NewDecoder(jsonFile)
	for dec.More() {
		var dbgErr *DebugError
		var ev tetragon.GetEventsResponse
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return &JsonEOFError{
					count: count,
					err:   fmt.Errorf("unmarshal failed: %w", err),
				}
			}
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
			log.Info(matchPrefix + " =>  FINAL MATCH")
			log.Info("jsonTestCheck: DONE!")
			return nil
		} else if err == nil {
			log.Info(matchPrefix + " => MATCH, continuing")
		} else if done && err != nil {
			log.Error(fmt.Sprintf("%s => terminating error: %s", matchPrefix, err))
			return err
		} else if errors.As(err, &dbgErr) {
			log.Debug(fmt.Sprintf("%s => no match: %s, continuing", matchPrefix, err))
		} else {
			log.Info(fmt.Sprintf("%s => no match: %s, continuing", matchPrefix, err))
		}
	}

	if err := checker.FinalCheck(log); err != nil {
		return &JsonEOFError{
			count: count,
			err:   err,
		}
	}
	return nil
}

func doJsonTestCheck(t *testing.T, jsonFile *os.File, checker ec.MultiEventChecker) error {
	cnt := 0
	prevEvents := 0
	var err error
	for {
		t0 := time.Now()
		err = JsonCheck(jsonFile, checker, logger.GetLogger())
		elapsed := time.Since(t0)
		t.Logf("JsonCheck (retry=%d) took %s", cnt, elapsed)
		if err == nil {
			break
		}

		// if this is not a JsonEOF error, it means that the checker
		// concluded that there was a falure. Dont retry.
		var errEOF *JsonEOFError
		if !errors.As(err, &errEOF) {
			break
		}

		// bail out if there are no new events in two consecutive runs
		if cnt > 0 && prevEvents == errEOF.count {
			err = fmt.Errorf("JsonTestCheck failed in retry cnt=%d and there were no new events from previous try: %w", cnt, err)
			break
		}
		prevEvents = errEOF.count

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

func JsonTestCheckExpect(t *testing.T, checker ec.MultiEventChecker, expectCheckerFailure bool) error {
	var err error

	jsonFname, err := testutils.GetExportFilename(t)
	if err != nil {
		return err
	}

	// NB: some tests will run JsonTestCheckExpect multiple times. Reset any previous
	// DoneWithExportFile from previous invocations.
	testutils.KeepExportFile(t)

	// attempt to open the export file
	t.Logf("jsonTestCheck: opening: %s\n", jsonFname)
	jsonFile, err := os.Open(jsonFname)
	if err != nil {
		return fmt.Errorf("opening json file failed: %w", err)
	}
	defer jsonFile.Close()

	err = doJsonTestCheck(t, jsonFile, checker)
	if expectCheckerFailure {
		if err == nil {
			err = errors.New("tester expected to fail, but succeeded")
		} else {
			err = nil
		}
	}

	if err == nil {
		// mark the file to be deleted
		if xerr := testutils.DoneWithExportFile(t); xerr != nil {
			// We failed to mark the file as deleted. This will happen if we hit a
			// timeout and .Close() already ran. Since we succeeded, let's just log a
			// message and delete the file.
			t.Logf("DoneWithExportFile failed: manually deleting file")
			os.Remove(jsonFname)
		}
	}
	return err
}

// JsonTestCheck checks a JSON file
func JsonTestCheck(t *testing.T, checker ec.MultiEventChecker) error {
	return JsonTestCheckExpect(t, checker, false)
}
