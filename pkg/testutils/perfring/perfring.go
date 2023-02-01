// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package perfring provides utilities to do tests using the perf ringbuffer directly
package perfring

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//revive:disable:context-as-argument

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/bpf"
	testapi "github.com/cilium/tetragon/pkg/grpc/test"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/notify"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/sirupsen/logrus"
)

// EventFn is the type of function called by ProcessEvents for each event.
type EventFn func(ev notify.Message) error

func loopEvents(events []observer.Event, eventFn EventFn, complChecker *testsensor.CompletionChecker) error {
	for _, ev := range events {
		switch xev := ev.(type) {
		case *testapi.MsgTestEventUnix:
			cpu := xev.Arg0
			complChecker.Update(cpu)
		}

		if err := eventFn(ev); err != nil {
			return err
		}
	}

	return nil
}

// ProcessEvents will open the perf ringbuffer and process events.
//
// It will complete, whenever it sees a number of MsgTestEventUnix on _all_
// cpus or when the ctx is done.  Hence, callers need to load the test sensor
// before they call it or use the ctx to cancel its operation.
//
// Example code to load the test sensor:
//
//	import testsensor "github.com/cilium/tetragon/pkg/sensors/test"
//	import tus "github.com/cilium/tetragon/pkg/testutils/sensors"
//	tus.LoadSensor(ctx, t, testsensor.GetTestSensor())
//
// If the test sensor is loaded, users can use TestCheckerMarkEnd to generate
// the appropriate MsgTestEventUnix.
func ProcessEvents(t *testing.T, ctx context.Context, eventFn EventFn, wgStarted *sync.WaitGroup) {
	pinOpts := ebpf.LoadPinOptions{}
	config := bpf.DefaultPerfEventConfig()

	perfMap, err := ebpf.LoadPinnedMap(config.MapName, &pinOpts)
	if err != nil {
		t.Fatalf("opening pinned map '%s' failed: %v", config.MapName, err)
	}
	defer perfMap.Close()

	perfReader, err := perf.NewReader(perfMap, 65535)
	if err != nil {
		t.Fatalf("creating perf array reader failed: %v", err)
	}

	wgStarted.Done()

	errChan := make(chan error)
	defer close(errChan)

	complChan := make(chan bool)
	defer close(complChan)

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	go func() {
		defer wg.Done()

		complChecker := testsensor.NewCompletionChecker()

		for {
			if ctx.Err() != nil {
				break
			}

			record, err := perfReader.Read()
			if err != nil {
				if ctx.Err() == nil {
					errChan <- fmt.Errorf("error reading perfring data: %v", err)
				}
				break
			}

			_, events, err := observer.HandlePerfData(record.RawSample)
			if err != nil {
				errChan <- fmt.Errorf("error handling perfring data: %v", err)
				break
			}
			err = loopEvents(events, eventFn, complChecker)
			if err != nil {
				errChan <- fmt.Errorf("error loop event function returned: %s", err)
				break
			}

			if complChecker.Done() {
				complChan <- true
				break
			}
		}
	}()

	for {
		select {
		case err := <-errChan:
			t.Fatal(err)
		case <-complChan:
			perfReader.Close()
			return
		case <-ctx.Done():
			// Wait for context cancel.
			perfReader.Close()
			return
		}
	}

}

// RunTest is a convinience wrapper around ProcessEvents
// it will:
//   - run ProcessEvents on a different goroutinem using eventFn
//   - execute selfOperations provided by the user
//   - execute TestCheckerMarkEnd so that ProcessEvents returns
//   - wait for ProcessEvents to finish, and return
func RunTest(t *testing.T, ctx context.Context, selfOperations func(), eventFn EventFn) {
	var wgDone, wgStarted sync.WaitGroup
	wgDone.Add(1)
	wgStarted.Add(1)
	go func() {
		defer wgDone.Done()
		ProcessEvents(t, ctx, eventFn, &wgStarted)
	}()
	wgStarted.Wait()
	selfOperations()
	testsensor.TestCheckerMarkEnd(t)
	wgDone.Wait()
}

func FilterTestMessages(n notify.Message) bool {
	_, ok := n.(*testapi.MsgTestEventUnix)
	return !ok
}

// RunTestEvents: returns a list of events after running the test with selfOperations (see RunTest)
// MsgTestEventUnix events are filtered out.
func RunTestEvents(t *testing.T, ctx context.Context, selfOperations func()) []notify.Message {
	return RunTestEventReduce(t, ctx, selfOperations,
		FilterTestMessages,
		func(x notify.Message) notify.Message {
			return x
		},
		func(arr []notify.Message, m notify.Message) []notify.Message {
			return append(arr, m)
		},
	)
}

func RunTestEventReduce[K any, V any](
	t *testing.T,
	ctx context.Context,
	selfOperations func(),
	filterFn func(notify.Message) bool,
	mapFn func(notify.Message) K,
	reduceFn func(val V, key K) V,
) V {
	var ret V
	RunTest(t, ctx, selfOperations, func(ev notify.Message) error {
		if !filterFn(ev) {
			return nil
		}
		key := mapFn(ev)
		ret = reduceFn(ret, key)
		return nil
	})
	return ret
}

// similar to RunTest, but uses t.Run()
func RunSubTest(t *testing.T, ctx context.Context, name string, selfOperations func(t *testing.T), eventFn EventFn) bool {
	return t.Run(name, func(t *testing.T) {
		testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
		RunTest(t, ctx, func() { selfOperations(t) }, eventFn)
	})
}
