// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/aggregator"
	pkgEvent "github.com/cilium/tetragon/pkg/event"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/google/uuid"
)

type Listener interface {
	Notify(res *tetragon.GetEventsResponse)
}

type Notifier interface {
	AddListener(listener Listener)
	RemoveListener(listener Listener)
	NotifyListener(original any, processed *tetragon.GetEventsResponse)
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
	logger.GetLogger().Debug("Received a GetEvents request",
		"events.allow_list", request.GetAllowList(),
		"events.deny_list", request.GetDenyList(),
		"events.field_filters", request.GetFieldFilters(),
		"events.aggregation_options", request.GetAggregationOptions())
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
			if !filters.Apply(allowList, denyList, &pkgEvent.Event{Event: event}) {
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
					logger.GetLogger().Warn("Failed to apply field filter", "filter", filter, logfields.Error, err)
					continue
				}
				event = ev
			}

			if aggregator != nil {
				// Send event to aggregator.
				select {
				case aggregator.GetEventChannel() <- event:
				default:
					logger.GetLogger().Warn("Aggregator buffer is full. Consider increasing AggregatorOptions.channel_buffer_size.",
						"request", request)
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
	logger.GetLogger().Debug("Received a GetHealth request", "request", request)
	return health.GetHealth()
}

func (s *Server) ListSensors(_ context.Context, _ *tetragon.ListSensorsRequest) (*tetragon.ListSensorsResponse, error) {
	logger.GetLogger().Debug("Received a ListSensors request")
	return nil, errors.New("ListSensors is deprecated")
}

func (s *Server) AddTracingPolicy(ctx context.Context, req *tetragon.AddTracingPolicyRequest) (*tetragon.AddTracingPolicyResponse, error) {
	tp, err := tracingpolicy.FromYAML(req.GetYaml())
	if err != nil {
		logger.GetLogger().Warn("Server AddTracingPolicy request failed", logfields.Error, err)
		return nil, err
	}
	namespace := ""
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	logger.GetLogger().Debug("Received an AddTracingPolicy request",
		"metadata.namespace", namespace,
		"metadata.name", tp.TpName())

	if err := s.observer.AddTracingPolicy(ctx, tp); err != nil {
		logger.GetLogger().Warn("Server AddTracingPolicy request failed",
			logfields.Error, err,
			"metadata.namespace", namespace,
			"metadata.name", tp.TpName())
		return nil, err
	}
	return &tetragon.AddTracingPolicyResponse{}, nil
}

func (s *Server) DeleteTracingPolicy(ctx context.Context, req *tetragon.DeleteTracingPolicyRequest) (*tetragon.DeleteTracingPolicyResponse, error) {
	logger.GetLogger().Debug("Received a DeleteTracingPolicy request", "name", req.GetName())

	if err := s.observer.DeleteTracingPolicy(ctx, req.GetName(), req.GetNamespace()); err != nil {
		logger.GetLogger().Warn("Server DeleteTracingPolicy request failed", "name", req.GetName(), logfields.Error, err)
		return nil, err
	}
	return &tetragon.DeleteTracingPolicyResponse{}, nil
}

func (s *Server) EnableTracingPolicy(ctx context.Context, req *tetragon.EnableTracingPolicyRequest) (*tetragon.EnableTracingPolicyResponse, error) {
	logger.GetLogger().Debug("Received a EnableTracingPolicy request", "name", req.GetName())

	if err := s.observer.EnableTracingPolicy(ctx, req.GetName(), req.GetNamespace()); err != nil {
		logger.GetLogger().Warn("Server EnableTracingPolicy request failed", "name", req.GetName(), logfields.Error, err)
		return nil, err
	}
	return &tetragon.EnableTracingPolicyResponse{}, nil
}
func (s *Server) ConfigureTracingPolicy(ctx context.Context, req *tetragon.ConfigureTracingPolicyRequest) (*tetragon.ConfigureTracingPolicyResponse, error) {
	logger.GetLogger().Debug("Received a ConfigureTrcingPolicy request", "name", req.GetName())

	if err := s.observer.ConfigureTracingPolicy(ctx, req); err != nil {
		return nil, err
	}

	return &tetragon.ConfigureTracingPolicyResponse{}, nil
}

func (s *Server) DisableTracingPolicy(ctx context.Context, req *tetragon.DisableTracingPolicyRequest) (*tetragon.DisableTracingPolicyResponse, error) {
	logger.GetLogger().Debug("Received a DisableTracingPolicy request", "name", req.GetName())

	if err := s.observer.DisableTracingPolicy(ctx, req.GetName(), req.GetNamespace()); err != nil {
		logger.GetLogger().Warn("Server DisableTracingPolicy request failed", "name", req.GetName(), logfields.Error, err)
		return nil, err
	}
	return &tetragon.DisableTracingPolicyResponse{}, nil
}

func (s *Server) ListTracingPolicies(ctx context.Context, req *tetragon.ListTracingPoliciesRequest) (*tetragon.ListTracingPoliciesResponse, error) {
	logger.GetLogger().Debug("Received a ListTracingPolicies request", "request", req)
	ret, err := s.observer.ListTracingPolicies(ctx)
	if err != nil {
		logger.GetLogger().Warn("Server ListTracingPolicies request failed", logfields.Error, err)
	}
	return ret, err
}

func (s *Server) RemoveSensor(_ context.Context, req *tetragon.RemoveSensorRequest) (*tetragon.RemoveSensorResponse, error) {
	logger.GetLogger().Debug("Received a RemoveSensor request", "sensor.name", req.GetName())
	return nil, errors.New("RemoveSensor is deprecated")
}

func (s *Server) EnableSensor(_ context.Context, req *tetragon.EnableSensorRequest) (*tetragon.EnableSensorResponse, error) {
	logger.GetLogger().Debug("Received a EnableSensor request", "sensor.name", req.GetName())
	return nil, errors.New("EnableSensor is deprecated")
}

func (s *Server) DisableSensor(_ context.Context, req *tetragon.DisableSensorRequest) (*tetragon.DisableSensorResponse, error) {
	logger.GetLogger().Debug("Received a DisableSensor request", "sensor.name", req.GetName())
	return nil, errors.New("DisableSensor is deprecated")
}

func (s *Server) GetStackTraceTree(_ context.Context, req *tetragon.GetStackTraceTreeRequest) (*tetragon.GetStackTraceTreeResponse, error) {
	logger.GetLogger().Debug("Received a GetStackTraceTree request", "request", req)
	err := errors.New("unsupported GetStackTraceTree")
	logger.GetLogger().Warn("Server GetStackTraceTree failed", logfields.Error, err)
	return nil, err
}

func (s *Server) GetVersion(_ context.Context, _ *tetragon.GetVersionRequest) (*tetragon.GetVersionResponse, error) {
	return &tetragon.GetVersionResponse{Version: version.Version}, nil
}

func (s *Server) RuntimeHook(ctx context.Context, req *tetragon.RuntimeHookRequest) (*tetragon.RuntimeHookResponse, error) {
	logger.GetLogger().Debug("Received a RuntimeHook request", "request", req)
	err := s.hookRunner.RunHooks(ctx, req)
	if err != nil {
		id := uuid.New()
		logger.GetLogger().Warn("server runtime hook failed", "logid", id, logfields.Error, err)
		return nil, fmt.Errorf("server runtime hook failed. Check agent logs with logid=%s for details", id)
	}
	return &tetragon.RuntimeHookResponse{}, nil
}

func (s *Server) GetDebug(_ context.Context, req *tetragon.GetDebugRequest) (*tetragon.GetDebugResponse, error) {
	switch req.GetFlag() {
	case tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL:
		logger.GetLogger().Debug("Client requested current log level: " + logger.GetLogLevel(logger.GetLogger()).String())
		return &tetragon.GetDebugResponse{
			Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
			Arg: &tetragon.GetDebugResponse_Level{
				Level: toTetragonLogLevel(logger.GetLogLevel(logger.GetLogger())),
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
		logger.GetLogger().Warn(fmt.Sprintf("Client requested unknown config flag %d", req.GetFlag()), "request", req)
		return nil, fmt.Errorf("client requested unknown config flag %d", req.GetFlag())
	}
}

func (s *Server) SetDebug(_ context.Context, req *tetragon.SetDebugRequest) (*tetragon.SetDebugResponse, error) {
	switch req.GetFlag() {
	case tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL:
		currentLogLevel := logger.GetLogLevel(logger.GetLogger())
		changedLogLevel := toSlogLevel(req.GetLevel())
		logger.SetLogLevel(changedLogLevel)
		logger.GetLogger().Warn(fmt.Sprintf("Log level changed from %s to %s", currentLogLevel, changedLogLevel), "request", req)
		return &tetragon.SetDebugResponse{
			Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
			Arg: &tetragon.SetDebugResponse_Level{
				Level: req.GetLevel(),
			},
		}, nil
	default:
		logger.GetLogger().Warn(fmt.Sprintf("Client requested change of unknown config flag %d", req.GetFlag()), "request", req)
		return nil, fmt.Errorf("client requested change of unknown config flag %d", req.GetFlag())
	}
}

func toTetragonLogLevel(level slog.Level) tetragon.LogLevel {
	switch level {
	case logger.LevelTrace:
		return tetragon.LogLevel_LOG_LEVEL_TRACE
	case slog.LevelDebug:
		return tetragon.LogLevel_LOG_LEVEL_DEBUG
	case slog.LevelInfo:
		return tetragon.LogLevel_LOG_LEVEL_INFO
	case slog.LevelWarn:
		return tetragon.LogLevel_LOG_LEVEL_WARN
	case slog.LevelError:
		return tetragon.LogLevel_LOG_LEVEL_ERROR
	case logger.LevelPanic:
		return tetragon.LogLevel_LOG_LEVEL_PANIC
	case logger.LevelFatal:
		return tetragon.LogLevel_LOG_LEVEL_FATAL
	default:
		return tetragon.LogLevel_LOG_LEVEL_INFO
	}
}

func toSlogLevel(level tetragon.LogLevel) slog.Level {
	switch level {
	case tetragon.LogLevel_LOG_LEVEL_TRACE:
		return logger.LevelTrace
	case tetragon.LogLevel_LOG_LEVEL_DEBUG:
		return slog.LevelDebug
	case tetragon.LogLevel_LOG_LEVEL_INFO:
		return slog.LevelInfo
	case tetragon.LogLevel_LOG_LEVEL_WARN:
		return slog.LevelWarn
	case tetragon.LogLevel_LOG_LEVEL_ERROR:
		return slog.LevelError
	case tetragon.LogLevel_LOG_LEVEL_PANIC:
		return logger.LevelPanic
	case tetragon.LogLevel_LOG_LEVEL_FATAL:
		return logger.LevelFatal
	default:
		return slog.LevelInfo
	}
}
