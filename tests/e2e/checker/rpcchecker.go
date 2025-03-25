// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package checker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ecYaml "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/yaml"
	eventHelpers "github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/multiplexer"
	"github.com/cilium/tetragon/tests/e2e/state"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/yaml"
)

// RPCChecker checks gRPC events from one or more events streams.
type RPCChecker struct {
	name             string
	checker          ec.MultiEventChecker
	getEvents        *multiplexer.ClientMultiplexer
	eventLimit       uint32
	timeLimit        time.Duration
	logs             *bytes.Buffer
	checkerStartedWG *sync.WaitGroup
	lock             *sync.Mutex
	encoder          exporter.ExportEncoder
	eventWriter      *bufio.Writer
	resetTimeout     chan struct{}
	resetEventCount  chan struct{}
}

// NewRPCChecker constructs a new RPCChecker from a MultiEventChecker.
func NewRPCChecker(checker ec.MultiEventChecker, name string) *RPCChecker {
	rc := &RPCChecker{
		name:             name,
		checker:          checker,
		getEvents:        nil,
		eventLimit:       0,
		timeLimit:        0,
		logs:             new(bytes.Buffer),
		checkerStartedWG: new(sync.WaitGroup),
		lock:             new(sync.Mutex),
		encoder:          nil,
		eventWriter:      nil,
		resetTimeout:     make(chan struct{}),
		resetEventCount:  make(chan struct{}),
	}
	// Mark that the checker has not yet started.
	rc.checkerStartedWG.Add(1)
	return rc
}

// WithEventLimit sets the event limit for an RPCChecker. If RPCChecker.Check sees more
// events than the limit, it stops the check loop, calls FinalCheck(), and returns its value.
func (rc *RPCChecker) WithEventLimit(limit uint32) *RPCChecker {
	rc.eventLimit = limit
	return rc
}

// WithTimeLimit sets the time limit for an RPCChecker. RPCChecker.Check takes longer
// than the time limit, it stops the check loop, calls FinalCheck(), and returns its value.
func (rc *RPCChecker) WithTimeLimit(limit time.Duration) *RPCChecker {
	rc.timeLimit = limit
	return rc
}

// Wait returns a features.Func that waits for the checker to have started its checks
// or fails the test on timeout.
func (rc *RPCChecker) Wait(waitTimeout time.Duration) features.Func {
	return func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
		if !cfg.ParallelTestEnabled() {
			assert.Fail(t, "rpc checker requires parallel tests to be enabled")
			return ctx
		}
		c := make(chan struct{})
		go func() {
			defer close(c)
			klog.V(2).InfoS("Waiting for checker to start...", "checker", rc.name)
			rc.checkerStartedWG.Wait()
			klog.V(2).InfoS("Done waiting for checker to start", "checker", rc.name)
		}()
		select {
		case <-time.After(waitTimeout):
			assert.Fail(t, fmt.Sprintf("failed to wait for checker %s to start after %s", rc.name, waitTimeout))
			return ctx
		case <-c:
			return ctx
		}
	}
}

// Check returns a feature func that runs event checks.
func (rc *RPCChecker) Check(connTimeout time.Duration) features.Func {
	return rc.CheckWithFilters(connTimeout, []*tetragon.Filter{}, []*tetragon.Filter{})
}

// CheckInNamespace returns a feature func that runs event checks on events filtered by
// one or more k8s namespaces.
func (rc *RPCChecker) CheckInNamespace(connTimeout time.Duration, namespaces ...string) features.Func {
	return rc.CheckWithFilters(connTimeout, []*tetragon.Filter{
		{
			Namespace: namespaces,
		},
	}, []*tetragon.Filter{})
}

// CheckInNamespace returns a feature func that runs event checks on events filtered by
// one or more filters.
func (rc *RPCChecker) CheckWithFilters(_ time.Duration, allowList, denyList []*tetragon.Filter) features.Func {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		// We acquire a lock here to avoid erroneously running this checker more than once
		// simultaneously in a testenv.TestInParallel call.
		rc.lock.Lock()
		defer rc.lock.Unlock()

		rc.logs.Reset()
		ctx = rc.updateContextEventCheckers(ctx)

		if dir, err := getExportDir(ctx); err != nil {
			klog.ErrorS(err, "failed to get export dir, refusing to export events from checker")
		} else {
			f, err := os.Create(filepath.Join(dir, rc.Name()+".eventchecker.events.json"))
			if err != nil {
				klog.ErrorS(err, "failed to create json export file, refusing to export events from checker")
			} else {
				rc.eventWriter = bufio.NewWriter(f)
				rc.encoder = json.NewEncoder(rc.eventWriter)
			}
		}

		connsMap, ok := ctx.Value(state.GrpcForwardedConns).(map[string]*grpc.ClientConn)
		if !ok {
			assert.Fail(t, "failed to find forwarded gRPC connections")
			return ctx
		}

		var conns []*grpc.ClientConn
		for _, conn := range connsMap {
			conns = append(conns, conn)
		}

		if rc.getEvents == nil {
			rc.setConns(conns)
		}

		if err := rc.check(ctx, allowList, denyList); !assert.NoError(t, err, "checks should pass") {
			return ctx
		}

		return ctx
	}
}

func (rc *RPCChecker) ResetTimeout() {
	rc.resetTimeout <- struct{}{}
}

func (rc *RPCChecker) ResetEventCount() {
	rc.resetEventCount <- struct{}{}
}

// Connect connects the RPCChecker to one or more gRPC servers. This must be called
// before calling RPCChecker.Check().
func (rc *RPCChecker) setConns(conns []*grpc.ClientConn) {
	cm := multiplexer.NewClientMultiplexer()
	cm.SetConns(conns)
	rc.getEvents = cm
}

// Check checks an event stream from one or more gRPC servers.
func (rc *RPCChecker) check(ctx context.Context, allowList, denyList []*tetragon.Filter) error {
	klog.InfoS("Running event checks", "checker", rc.name)

	getEventsCtx, cancelGetEvents := context.WithCancel(ctx)
	defer cancelGetEvents()
	c, err := rc.getEvents.GetEvents(getEventsCtx, allowList, denyList)
	if err != nil {
		return err
	}

	timeout := time.NewTimer(rc.timeLimit)
	var eventCount uint32

	// Invariant rc.checkerStartedWG counter must be == 1 here
	klog.V(2).Info("Marking event checker as ready", "checker", rc.name)
	rc.checkerStartedWG.Done()
	// When the checks are finished, we want to once again mark that the checker not yet
	// started (in case other goroutines want to wait for the same checker again).
	defer rc.checkerStartedWG.Add(1)
	// Flush the event writer at the end
	defer func() {
		if rc.eventWriter != nil {
			rc.eventWriter.Flush()
		}
	}()
	// Dump unmatched checks at the end
	defer func() {
		checker, ok := rc.checker.(interface{ GetRemainingChecks() []ec.EventChecker })
		if !ok {
			klog.ErrorS(fmt.Errorf("checker has no method GetRemainingChecks()"), "unable to dump remaining checks")
			return
		}
		if err := dumpChecks(ctx, rc.Name(), checker.GetRemainingChecks()); err != nil {
			klog.ErrorS(err, "failed to dump unmatched checks")
		}
	}()

	for {
		select {
		case <-rc.resetTimeout:
			if !timeout.Stop() {
				<-timeout.C
			}
			timeout = time.NewTimer(rc.timeLimit)
			continue
		case <-rc.resetEventCount:
			eventCount = 0
			continue
		case <-timeout.C:
			if rc.timeLimit > 0 {
				klog.Infof("event checker %s timed out after %v", rc.name, rc.timeLimit)
				return rc.checker.FinalCheck(nil)
			}
		case res := <-c:
			err := res.Error
			event := res.GetEventsResponse

			if event == nil || err != nil && !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				rc.checker.FinalCheck(nil) // reset event checker
				return fmt.Errorf("event checker %s failed to receive event: %w", rc.name, err)
			}

			if rc.encoder != nil && rc.eventWriter != nil {
				rc.encoder.Encode(event)
			}

			eventCount++
			eventType, err := eventHelpers.ResponseTypeString(event)
			if err != nil {
				klog.ErrorS(err, "failed to get event type")
				eventType = "UNKNOWN"
			}
			prefix := fmt.Sprintf("%s:%d", eventType, eventCount)

			if rc.eventLimit > 0 && eventCount > rc.eventLimit {
				klog.Infof("event limit of %d exceeded for checker %s", rc.eventLimit, rc.name)
				return rc.checker.FinalCheck(nil)
			}

			// FIXME: refactor eventchecker so we can use klog here
			log := logger.GetLogger().(*logrus.Logger)
			mw := io.MultiWriter(os.Stderr, rc.logs)
			log.SetOutput(mw)

			done, err := ec.NextResponseCheck(rc.checker, event, log)
			if done && err == nil {
				log.Infof("%s => FINAL MATCH ", prefix)
				log.Infof("DONE!")
				rc.checker.FinalCheck(nil) // reset event checker
				return nil
			} else if err == nil {
				log.Infof("%s => MATCH, continuing", prefix)
			} else if done {
				log.Errorf("%s => terminating error: %s", prefix, err)
				rc.checker.FinalCheck(nil) // reset event checker
				return err
			} else {
				log.Infof("%s => no match: %s, continuing", prefix, err)
			}
		}
	}
}

// Name returns the name of the checker
func (rc *RPCChecker) Name() string {
	return rc.name
}

// CheckerYaml dumps the inner checker's yaml definition
func (rc *RPCChecker) CheckerYaml() (string, error) {
	spec, err := ecYaml.SpecFromMultiEventChecker(rc.checker)
	if err != nil {
		return "", err
	}
	out, err := yaml.Marshal(spec)
	if err != nil {
		return "", err
	}
	return string(out), err
}

func (rc *RPCChecker) Logs() []byte {
	return rc.logs.Bytes()
}

func (rc *RPCChecker) updateContextEventCheckers(ctx context.Context) context.Context {
	if checkers, ok := ctx.Value(state.EventCheckers).(map[string]*RPCChecker); ok {
		checkers[rc.name] = rc
		return context.WithValue(ctx, state.EventCheckers, checkers)
	}
	checkers := make(map[string]*RPCChecker)
	checkers[rc.name] = rc
	return context.WithValue(ctx, state.EventCheckers, checkers)
}

func getExportDir(ctx context.Context) (string, error) {
	exportDir, ok := ctx.Value(state.ExportDir).(string)
	if !ok {
		return "", fmt.Errorf("export dir has not been created. Call helpers.CreateExportDir() first")
	}
	return exportDir, nil
}

func checkertypeString(checker ec.EventChecker) string {
	// Get the concrete type of the event
	ty := fmt.Sprintf("%T", checker)
	// Take only what comes after the last "."
	tys := strings.Split(ty, ".")
	ty = tys[len(tys)-1]
	return ty
}

func dumpChecks(ctx context.Context, checkerName string, checks []ec.EventChecker) error {
	var unmatchedChecks []map[string]interface{}

	for _, check := range checks {
		unmatchedChecks = append(unmatchedChecks, map[string]interface{}{checkertypeString(check): check})
	}

	exportDir, err := getExportDir(ctx)
	if err != nil {
		return err
	}

	fname := checkerName + ".eventchecker.unmatched.json"
	f, err := os.Create(filepath.Join(exportDir, fname))
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", fname, err)
	}

	encoder := json.NewEncoder(f)
	err = encoder.Encode(unmatchedChecks)
	if err != nil {
		return fmt.Errorf("failed encode unmatched checks: %w", err)

	}

	return nil
}
