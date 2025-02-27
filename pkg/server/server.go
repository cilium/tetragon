// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"context"
	"fmt"
	"io"
	"sync"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleFilters "github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/aggregator"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type Listener interface {
	Notify(res *tetragon.GetEventsResponse)
}

type Notifier interface {
	AddListener(listener Listener)
	RemoveListener(listener Listener)
	NotifyListener(original interface{}, processed *tetragon.GetEventsResponse)
}

type observer interface {
	// AddTracingPolicy will add a new tracing policy
	AddTracingPolicy(ctx context.Context, policy tracingpolicy.TracingPolicy) error
	// DeleteTracingPolicy deletes a tracing policy that was added with
	// AddTracingPolicy as defined by its name (policy.TpName()).
	DeleteTracingPolicy(ctx context.Context, name string, namespace string) error
	// ListTracingPolicies lists active traing policies
	ListTracingPolicies(ctx context.Context) (*tetragon.ListTracingPoliciesResponse, error)
	ConfigureTracingPolicy(ctx context.Context, conf *tetragon.ConfigureTracingPolicyRequest) error

	// {Disable, Enable}TracingPolicy are deprecated, use ConfigureTracingPolicy instead
	DisableTracingPolicy(ctx context.Context, name string, namespace string) error
	EnableTracingPolicy(ctx context.Context, name string, namespace string) error
}

type hookRunner interface {
	RunHooks(ctx context.Context, req *tetragon.RuntimeHookRequest) error
}

type Server struct {
	ctx          context.Context
	ctxCleanupWG *sync.WaitGroup
	notifier     Notifier
	observer     observer
	hookRunner   hookRunner
	tetragon.UnimplementedFineGuidanceSensorsServer
}

type getEventsListener struct {
	events chan *tetragon.GetEventsResponse
}

func NewServer(ctx context.Context, cleanupWg *sync.WaitGroup, notifier Notifier, observer observer, hookRunner hookRunner) *Server {
	return &Server{
		ctx:          ctx,
		ctxCleanupWG: cleanupWg,
		notifier:     notifier,
		observer:     observer,
		hookRunner:   hookRunner,
	}
}

func newListener() *getEventsListener {
	var chanSize uint = 10000
	if option.Config.EventQueueSize > 0 {
		chanSize = option.Config.EventQueueSize
	}
	return &getEventsListener{
		events: make(chan *tetragon.GetEventsResponse, chanSize),
	}
}

func (l *getEventsListener) Notify(res *tetragon.GetEventsResponse) {
	select {
	case l.events <- res:
	default:
		// events channel is full: drop the event so that we do not block everything
		eventmetrics.NotifyOverflowedEvents.Inc()
	}
}

// removeNotifierAndDrain removes the events listener while draining
// any events that may arrive during removal. This is required in order
// not to deadlock the process manager.
func (s *Server) removeNotifierAndDrain(l *getEventsListener) {
	done := make(chan struct{})
	go func() {
		s.notifier.RemoveListener(l)
		done <- struct{}{}
	}()

	for {
		select {
		case <-l.events:
		case <-done:
			return
		}
	}
}
func (s *Server) GetEvents(request *tetragon.GetEventsRequest, server tetragon.FineGuidanceSensors_GetEventsServer) error {
	return s.GetEventsWG(request, server, nil, nil)
}

func (s *Server) GetEventsWG(request *tetragon.GetEventsRequest, server tetragon.FineGuidanceSensors_GetEventsServer, closer io.Closer, readyWG *sync.WaitGroup) error {
	logger.GetLogger().WithFields(logrus.Fields{
		"events.allow_list":          request.GetAllowList(),
		"events.deny_list":           request.GetDenyList(),
		"events.field_filters":       request.GetFieldFilters(),
		"events.aggregation_options": request.GetAggregationOptions(),
	}).Debug("Received a GetEvents request")
	allowList, err := filters.BuildFilterList(s.ctx, request.AllowList, filters.Filters)
	if err != nil {
		if readyWG != nil {
			readyWG.Done()
		}
		return err
	}
	denyList, err := filters.BuildFilterList(s.ctx, request.DenyList, filters.Filters)
	if err != nil {
		if readyWG != nil {
			readyWG.Done()
		}
		return err
	}
	aggregator, err := aggregator.NewAggregator(server, request.AggregationOptions)
	if err != nil {
		if readyWG != nil {
			readyWG.Done()
		}
		return err
	}
	if aggregator != nil {
		go aggregator.Start()
	}

	l := newListener()
	s.notifier.AddListener(l)
	defer s.removeNotifierAndDrain(l)
	if readyWG != nil {
		readyWG.Done()
	}
	s.ctxCleanupWG.Add(1)
	defer s.ctxCleanupWG.Done()
	for {
		select {
		case event := <-l.events:
			if !hubbleFilters.Apply(allowList, denyList, &v1.Event{Event: event}) {
				// Event is filtered out. Nothing to do here. Continue.
				continue
			}

			// Get field filters
			filters, err := fieldfilters.FieldFiltersFromGetEventsRequest(request)
			if err != nil {
				return fmt.Errorf("failed to create field filters: %w", err)
			}

			// Apply field filters
			for _, filter := range filters {
				ev, err := filter.Filter(event)
				if err != nil {
					logger.GetLogger().WithField("filter", filter).WithError(err).Warn("Failed to apply field filter")
					continue
				}
				event = ev
			}

			if aggregator != nil {
				// Send event to aggregator.
				select {
				case aggregator.GetEventChannel() <- event:
				default:
					logger.GetLogger().
						WithField("request", request).
						Warn("Aggregator buffer is full. Consider increasing AggregatorOptions.channel_buffer_size.")
				}
			} else {
				// No need to aggregate. Directly send out the response.
				if err = server.Send(event); err != nil {
					return err
				}
			}
		case <-server.Context().Done():
			if closer != nil {
				closer.Close()
			}
			return server.Context().Err()
		case <-s.ctx.Done():
			if closer != nil {
				closer.Close()
			}
			return s.ctx.Err()
		}
	}
}

func (s *Server) GetHealth(_ context.Context, request *tetragon.GetHealthStatusRequest) (*tetragon.GetHealthStatusResponse, error) {
	logger.GetLogger().WithField("request", request).Debug("Received a GetHealth request")
	return health.GetHealth()
}

func (s *Server) ListSensors(_ context.Context, _ *tetragon.ListSensorsRequest) (*tetragon.ListSensorsResponse, error) {
	logger.GetLogger().Debug("Received a ListSensors request")
	return nil, fmt.Errorf("ListSensors is deprecated")
}

func (s *Server) AddTracingPolicy(ctx context.Context, req *tetragon.AddTracingPolicyRequest) (*tetragon.AddTracingPolicyResponse, error) {
	tp, err := tracingpolicy.FromYAML(req.GetYaml())
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Server AddTracingPolicy request failed")
		return nil, err
	}
	namespace := ""
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"metadata.namespace": namespace,
		"metadata.name":      tp.TpName(),
	}).Debug("Received an AddTracingPolicy request")

	if err := s.observer.AddTracingPolicy(ctx, tp); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"metadata.namespace": namespace,
			"metadata.name":      tp.TpName(),
		}).WithError(err).Warn("Server AddTracingPolicy request failed")
		return nil, err
	}
	return &tetragon.AddTracingPolicyResponse{}, nil
}

func (s *Server) DeleteTracingPolicy(ctx context.Context, req *tetragon.DeleteTracingPolicyRequest) (*tetragon.DeleteTracingPolicyResponse, error) {
	logger.GetLogger().WithFields(logrus.Fields{
		"name": req.GetName(),
	}).Debug("Received a DeleteTracingPolicy request")

	if err := s.observer.DeleteTracingPolicy(ctx, req.GetName(), req.GetNamespace()); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": req.GetName(),
		}).WithError(err).Warn("Server DeleteTracingPolicy request failed")
		return nil, err
	}
	return &tetragon.DeleteTracingPolicyResponse{}, nil
}

func (s *Server) EnableTracingPolicy(ctx context.Context, req *tetragon.EnableTracingPolicyRequest) (*tetragon.EnableTracingPolicyResponse, error) {
	logger.GetLogger().WithFields(logrus.Fields{
		"name": req.GetName(),
	}).Debug("Received a EnableTracingPolicy request")

	if err := s.observer.EnableTracingPolicy(ctx, req.GetName(), req.GetNamespace()); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": req.GetName(),
		}).WithError(err).Warn("Server EnableTracingPolicy request failed")
		return nil, err
	}
	return &tetragon.EnableTracingPolicyResponse{}, nil
}
func (s *Server) ConfigureTracingPolicy(ctx context.Context, req *tetragon.ConfigureTracingPolicyRequest) (*tetragon.ConfigureTracingPolicyResponse, error) {
	logger.GetLogger().WithFields(logrus.Fields{
		"name": req.GetName(),
	}).Debug("Received a ConfigureTrcingPolicy request")

	if err := s.observer.ConfigureTracingPolicy(ctx, req); err != nil {
		return nil, err
	}

	return &tetragon.ConfigureTracingPolicyResponse{}, nil
}

func (s *Server) DisableTracingPolicy(ctx context.Context, req *tetragon.DisableTracingPolicyRequest) (*tetragon.DisableTracingPolicyResponse, error) {
	logger.GetLogger().WithFields(logrus.Fields{
		"name": req.GetName(),
	}).Debug("Received a DisableTracingPolicy request")

	if err := s.observer.DisableTracingPolicy(ctx, req.GetName(), req.GetNamespace()); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": req.GetName(),
		}).WithError(err).Warn("Server DisableTracingPolicy request failed")
		return nil, err
	}
	return &tetragon.DisableTracingPolicyResponse{}, nil
}

func (s *Server) ListTracingPolicies(ctx context.Context, req *tetragon.ListTracingPoliciesRequest) (*tetragon.ListTracingPoliciesResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a ListTracingPolicies request")
	ret, err := s.observer.ListTracingPolicies(ctx)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Server ListTracingPolicies request failed")
	}
	return ret, err
}

func (s *Server) RemoveSensor(_ context.Context, req *tetragon.RemoveSensorRequest) (*tetragon.RemoveSensorResponse, error) {
	logger.GetLogger().WithField("sensor.name", req.GetName()).Debug("Received a RemoveSensor request")
	return nil, fmt.Errorf("RemoveSensor is deprecated")
}

func (s *Server) EnableSensor(_ context.Context, req *tetragon.EnableSensorRequest) (*tetragon.EnableSensorResponse, error) {
	logger.GetLogger().WithField("sensor.name", req.GetName()).Debug("Received a EnableSensor request")
	return nil, fmt.Errorf("EnableSensor is deprecated")
}

func (s *Server) DisableSensor(_ context.Context, req *tetragon.DisableSensorRequest) (*tetragon.DisableSensorResponse, error) {
	logger.GetLogger().WithField("sensor.name", req.GetName()).Debug("Received a DisableSensor request")
	return nil, fmt.Errorf("DisableSensor is deprecated")
}

func (s *Server) GetStackTraceTree(_ context.Context, req *tetragon.GetStackTraceTreeRequest) (*tetragon.GetStackTraceTreeResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a GetStackTraceTree request")
	err := fmt.Errorf("Unsupported GetStackTraceTree")
	logger.GetLogger().WithError(err).Warn("Server GetStackTraceTree failed")
	return nil, err
}

func (s *Server) GetVersion(_ context.Context, _ *tetragon.GetVersionRequest) (*tetragon.GetVersionResponse, error) {
	return &tetragon.GetVersionResponse{Version: version.Version}, nil
}

func (s *Server) RuntimeHook(ctx context.Context, req *tetragon.RuntimeHookRequest) (*tetragon.RuntimeHookResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a RuntimeHook request")
	err := s.hookRunner.RunHooks(ctx, req)
	if err != nil {
		id := uuid.New()
		logger.GetLogger().WithFields(logrus.Fields{
			"logid": id,
		}).WithError(err).Warn("server runtime hook failed")
		return nil, fmt.Errorf("server runtime hook failed. Check agent logs with logid=%s for details", id)
	}
	return &tetragon.RuntimeHookResponse{}, nil
}

func (s *Server) GetDebug(_ context.Context, req *tetragon.GetDebugRequest) (*tetragon.GetDebugResponse, error) {
	switch req.GetFlag() {
	case tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL:
		logger.GetLogger().Debugf("Client requested current log level: %s", logger.GetLogLevel().String())
		return &tetragon.GetDebugResponse{
			Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
			Arg: &tetragon.GetDebugResponse_Level{
				Level: tetragon.LogLevel(logger.GetLogLevel()),
			},
		}, nil
	case tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE:
		logger.GetLogger().Debug("Client requested dump of process cache")
		res := tetragon.DumpProcessCacheResArgs{
			Processes: process.DumpProcessCache(req.GetDump()),
		}
		return &tetragon.GetDebugResponse{
			Flag: tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE,
			Arg: &tetragon.GetDebugResponse_Processes{
				Processes: &res,
			},
		}, nil
	default:
		logger.GetLogger().WithField("request", req).Warnf("Client requested unknown config flag %d", req.GetFlag())
		return nil, fmt.Errorf("client requested unknown config flag %d", req.GetFlag())
	}
}

func (s *Server) SetDebug(_ context.Context, req *tetragon.SetDebugRequest) (*tetragon.SetDebugResponse, error) {
	switch req.GetFlag() {
	case tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL:
		currentLogLevel := logger.GetLogLevel()
		changedLogLevel := logrus.Level(req.GetLevel())
		logger.SetLogLevel(changedLogLevel)
		logger.GetLogger().WithField("request", req).Warnf("Log level changed from %s to %s", currentLogLevel, changedLogLevel.String())
		return &tetragon.SetDebugResponse{
			Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
			Arg: &tetragon.SetDebugResponse_Level{
				Level: tetragon.LogLevel(changedLogLevel),
			},
		}, nil
	default:
		logger.GetLogger().WithField("request", req).Warnf("Client requested change of unknown config flag %d", req.GetFlag())
		return nil, fmt.Errorf("client requested change of unknown config flag %d", req.GetFlag())
	}
}
