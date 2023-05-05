// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/aggregator"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/sirupsen/logrus"
)

type Listener interface {
	Notify(res *tetragon.GetEventsResponse)
}

type notifier interface {
	AddListener(listener Listener)
	RemoveListener(listener Listener)
	NotifyListener(original interface{}, processed *tetragon.GetEventsResponse)
}

type observer interface {
	// AddTracingPolicy will add a new tracing policy
	AddTracingPolicy(ctx context.Context, policy tracingpolicy.TracingPolicy) error
	// DelTracingPolicy deletes a tracing policy that was added with
	// AddTracingPolicy as defined by  its name (policy.TpName()).
	DelTracingPolicy(ctx context.Context, name string) error
	// ListTracingPolicies lists active traing policies
	ListTracingPolicies(ctx context.Context) (*tetragon.ListTracingPoliciesResponse, error)

	EnableSensor(ctx context.Context, name string) error
	DisableSensor(ctx context.Context, name string) error
	ListSensors(ctx context.Context) (*[]sensors.SensorStatus, error)
	GetSensorConfig(ctx context.Context, name string, cfgkey string) (string, error)
	SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error
	RemoveSensor(ctx context.Context, sensorName string) error
}

type hookRunner interface {
	RunHooks(ctx context.Context, req *tetragon.RuntimeHookRequest) error
}

type Server struct {
	ctx          context.Context
	ctxCleanupWG *sync.WaitGroup
	notifier     notifier
	observer     observer
	hookRunner   hookRunner
}

type getEventsListener struct {
	events chan *tetragon.GetEventsResponse
}

func NewServer(ctx context.Context, cleanupWg *sync.WaitGroup, notifier notifier, observer observer, hookRunner hookRunner) *Server {
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
		eventmetrics.NotifyOverflowedEvents.WithLabelValues().Inc()
	}
}

func (s *Server) NotifyListeners(original interface{}, processed *tetragon.GetEventsResponse) {
	s.notifier.NotifyListener(original, processed)
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
		return err
	}
	denyList, err := filters.BuildFilterList(s.ctx, request.DenyList, filters.Filters)
	if err != nil {
		return err
	}
	aggregator, err := aggregator.NewAggregator(server, request.AggregationOptions)
	if err != nil {
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
	for {
		select {
		case event := <-l.events:
			if !hubbleFilters.Apply(allowList, denyList, &v1.Event{Event: event}) {
				// Event is filtered out. Nothing to do here. Continue.
				continue
			}

			// Filter the GetEventsResponse fields
			filters := filters.FieldFiltersFromGetEventsRequest(request)
			for _, filter := range filters {
				filter.Filter(event)
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
					s.ctxCleanupWG.Done()
					return err
				}
			}
		case <-server.Context().Done():
			if closer != nil {
				closer.Close()
			}
			s.ctxCleanupWG.Done()
			return server.Context().Err()
		case <-s.ctx.Done():
			if closer != nil {
				closer.Close()
			}
			s.ctxCleanupWG.Done()
			return s.ctx.Err()
		}
	}
}

func (s *Server) GetHealth(_ context.Context, request *tetragon.GetHealthStatusRequest) (*tetragon.GetHealthStatusResponse, error) {
	logger.GetLogger().WithField("request", request).Debug("Received a GetHealth request")
	return health.GetHealth()
}

func (s *Server) ListSensors(ctx context.Context, _ *tetragon.ListSensorsRequest) (*tetragon.ListSensorsResponse, error) {
	logger.GetLogger().Debug("Received a ListSensors request")
	list, err := s.observer.ListSensors(ctx)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Server ListSensors request failed")
		return nil, err
	}

	sensors := make([]*tetragon.SensorStatus, 0, len(*list))
	for _, s := range *list {
		sensors = append(sensors, &tetragon.SensorStatus{
			Name:       s.Name,
			Enabled:    s.Enabled,
			Collection: s.Collection,
		})
	}

	return &tetragon.ListSensorsResponse{Sensors: sensors}, nil
}

func (s *Server) AddTracingPolicy(ctx context.Context, req *tetragon.AddTracingPolicyRequest) (*tetragon.AddTracingPolicyResponse, error) {
	tp, err := config.PolicyFromYaml(req.GetYaml())
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

func (s *Server) DelTracingPolicy(ctx context.Context, req *tetragon.DeleteTracingPolicyRequest) (*tetragon.DeleteTracingPolicyResponse, error) {
	tp, err := config.PolicyFromYaml(req.GetYaml())
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Server DeleteTracingPolicy request failed")
		return nil, err
	}
	namespace := ""
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"metadata.namespace": namespace,
		"metadata.name":      tp.TpName(),
	}).Debug("Received a DeleteTracingPolicy request")

	if err := s.observer.DelTracingPolicy(ctx, tp.TpName()); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"metadata.namespace": namespace,
			"metadata.name":      tp.TpName(),
		}).WithError(err).Warn("Server DeleteTracingPolicy request failed")
		return nil, err
	}
	return &tetragon.DeleteTracingPolicyResponse{}, nil
}

func (s *Server) ListTracingPolicies(ctx context.Context, req *tetragon.ListTracingPoliciesRequest) (*tetragon.ListTracingPoliciesResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a ListTracingPolicies request")
	ret, err := s.observer.ListTracingPolicies(ctx)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Server ListTracingPolicies request failed")
	}
	return ret, err
}

func (s *Server) RemoveSensor(ctx context.Context, req *tetragon.RemoveSensorRequest) (*tetragon.RemoveSensorResponse, error) {
	logger.GetLogger().WithField("sensor.name", req.GetName()).Debug("Received a RemoveSensor request")
	if err := s.observer.RemoveSensor(ctx, req.GetName()); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"sensor.name": req.GetName(),
		}).WithError(err).Warn("Server RemoveSensor request failed")
		return nil, err
	}
	return &tetragon.RemoveSensorResponse{}, nil
}

func (s *Server) EnableSensor(ctx context.Context, req *tetragon.EnableSensorRequest) (*tetragon.EnableSensorResponse, error) {
	logger.GetLogger().WithField("sensor.name", req.GetName()).Debug("Received a EnableSensor request")
	err := s.observer.EnableSensor(ctx, req.GetName())
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"sensor.name": req.GetName(),
		}).WithError(err).Warn("Server EnableSensor request failed")
		return nil, err
	}

	return &tetragon.EnableSensorResponse{}, nil
}

func (s *Server) DisableSensor(ctx context.Context, req *tetragon.DisableSensorRequest) (*tetragon.DisableSensorResponse, error) {
	logger.GetLogger().WithField("sensor.name", req.GetName()).Debug("Received a DisableSensor request")
	err := s.observer.DisableSensor(ctx, req.GetName())
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"sensor.name": req.GetName(),
		}).WithError(err).Warn("Server DisableSensor request failed")
		return nil, err
	}

	return &tetragon.DisableSensorResponse{}, nil
}

func (s *Server) GetSensorConfig(ctx context.Context, req *tetragon.GetSensorConfigRequest) (*tetragon.GetSensorConfigResponse, error) {
	logger.GetLogger().WithFields(logrus.Fields{
		"sensor.name":   req.GetName(),
		"sensor.config": req.GetCfgkey(),
	}).Debug("Received a GetSensorConfig request")
	cfgval, err := s.observer.GetSensorConfig(ctx, req.GetName(), req.GetCfgkey())
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"sensor.name":   req.GetName(),
			"sensor.config": req.GetCfgkey(),
		}).WithError(err).Warn("Server GetSensorConfig request failed")
		return nil, err
	}

	return &tetragon.GetSensorConfigResponse{Cfgval: cfgval}, nil
}

func (s *Server) SetSensorConfig(ctx context.Context, req *tetragon.SetSensorConfigRequest) (*tetragon.SetSensorConfigResponse, error) {
	logger.GetLogger().WithFields(logrus.Fields{
		"sensor.name":         req.GetName(),
		"sensor.config":       req.GetCfgkey(),
		"sensor.config.value": req.GetCfgval(),
	}).Debug("Received a SetSensorConfig request")
	err := s.observer.SetSensorConfig(ctx, req.GetName(), req.GetCfgkey(), req.GetCfgval())
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"sensor.name":   req.GetName(),
			"sensor.config": req.GetCfgkey(),
		}).WithError(err).Warn("Server SetSensorConfig request failed")
		return nil, err
	}

	return &tetragon.SetSensorConfigResponse{}, nil
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
		logger.GetLogger().WithField("request", req).WithError(err).Warn("Server RuntimeHook failed")
	}
	return &tetragon.RuntimeHookResponse{}, nil
}
