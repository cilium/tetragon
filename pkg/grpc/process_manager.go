// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package grpc

import (
	"fmt"
	"sync"

	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/dns"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/execcache"
	"github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/grpc/test"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/sirupsen/logrus"
)

type execProcess interface {
	HandleExecveMessage(*processapi.MsgExecveEventUnix) *tetragon.GetEventsResponse
	HandleExitMessage(*processapi.MsgExitEventUnix) *tetragon.GetEventsResponse
	HandleCloneMessage(*processapi.MsgCloneEventUnix)
}

var (
	tracingGrpc *tracing.Grpc
	execGrpc    execProcess
)

// ProcessManager maintains a cache of processes from tetragon exec events.
type ProcessManager struct {
	eventCache *eventcache.Cache
	execCache  *execcache.Cache
	nodeName   string
	Server     *server.Server
	// synchronize access to the listeners map.
	mux               sync.Mutex
	listeners         map[server.Listener]struct{}
	ciliumState       *cilium.State
	enableProcessCred bool
	enableProcessNs   bool
	enableEventCache  bool
	enableCilium      bool
	dns               *dns.Cache
}

// NewProcessManager returns a pointer to an initialized ProcessManager struct.
func NewProcessManager(
	ciliumState *cilium.State,
	manager *sensors.Manager,
	enableProcessCred bool,
	enableProcessNs bool,
	enableEventCache bool,
	enableCilium bool,
) (*ProcessManager, error) {
	var err error

	pm := &ProcessManager{
		nodeName:          node.GetNodeNameForExport(),
		ciliumState:       ciliumState,
		listeners:         make(map[server.Listener]struct{}),
		enableProcessCred: enableProcessCred,
		enableProcessNs:   enableProcessNs,
		enableEventCache:  enableEventCache,
		enableCilium:      enableCilium,
	}

	pm.dns, err = dns.NewCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS cache %w", err)
	}
	pm.Server = server.NewServer(pm, manager)
	pm.eventCache = eventcache.New(pm.Server, pm.dns)
	pm.execCache = execcache.New(pm.Server, pm.dns)

	tracingGrpc = tracing.New(ciliumState, pm.dns, pm.eventCache, enableCilium, enableProcessCred, enableProcessNs)
	execGrpc = exec.New(pm.execCache, pm.eventCache, enableProcessCred, enableProcessNs)

	logger.GetLogger().WithField("enableCilium", enableCilium).WithFields(logrus.Fields{
		"enableEventCache":  enableEventCache,
		"enableProcessCred": enableProcessCred,
		"enableProcessNs":   enableProcessNs,
	}).Info("Starting process manager")
	return pm, nil
}

// Notify implements Listener.Notify.
func (pm *ProcessManager) Notify(event interface{}) error {
	var processedEvent *tetragon.GetEventsResponse
	switch msg := event.(type) {
	case *readyapi.MsgTETRAGONReady:
		// pass
	case *processapi.MsgExecveEventUnix:
		processedEvent = execGrpc.HandleExecveMessage(msg)
	case *processapi.MsgCloneEventUnix:
		execGrpc.HandleCloneMessage(msg)
	case *processapi.MsgExitEventUnix:
		processedEvent = execGrpc.HandleExitMessage(msg)
	case *tracingapi.MsgGenericKprobeUnix:
		processedEvent = tracingGrpc.HandleGenericKprobeMessage(msg)
	case *tracingapi.MsgGenericTracepointUnix:
		processedEvent = tracingGrpc.HandleGenericTracepointMessage(msg)
	case *testapi.MsgTestEventUnix:
		processedEvent = test.HandleTestMessage(msg)

	default:
		logger.GetLogger().WithField("event", event).Warnf("unhandled event of type %T", msg)
		metrics.ErrorCount.WithLabelValues(string(metrics.UnhandledEvent)).Inc()
		return nil
	}
	if processedEvent != nil {
		pm.NotifyListener(event, processedEvent)
	}
	return nil
}

// Close implements Listener.Close.
func (pm *ProcessManager) Close() error {
	return nil
}

func (pm *ProcessManager) AddListener(listener server.Listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Adding a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	pm.listeners[listener] = struct{}{}
}

func (pm *ProcessManager) RemoveListener(listener server.Listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Removing a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	delete(pm.listeners, listener)
}

func (pm *ProcessManager) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	pm.mux.Lock()
	defer pm.mux.Unlock()
	for l := range pm.listeners {
		l.Notify(processed)
	}
	metrics.ProcessEvent(original, processed)
}
