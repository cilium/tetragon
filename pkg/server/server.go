// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"context"
	"sync"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/pkg/aggregator"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/version"
)

type Listener interface {
	Notify(res *fgs.GetEventsResponse)
}

type notifier interface {
	AddListener(listener Listener)
	RemoveListener(listener Listener)
	NotifyListener(original interface{}, processed *fgs.GetEventsResponse)
}

type observer interface {
	AddTracingPolicy(ctx context.Context, sensorName string, spec *v1alpha1.TracingPolicySpec) error
	DelTracingPolicy(ctx context.Context, sensorName string) error
	EnableSensor(ctx context.Context, name string) error
	DisableSensor(ctx context.Context, name string) error
	ListSensors(ctx context.Context) (*[]sensors.SensorStatus, error)
	GetSensorConfig(ctx context.Context, name string, cfgkey string) (string, error)
	SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error
	RemoveSensor(ctx context.Context, sensorName string) error
	GetTreeProto(ctx context.Context, tname string) (*fgs.StackTraceNode, error)
}

type Server struct {
	notifier notifier
	observer observer
}

type getEventsListener struct {
	events chan *fgs.GetEventsResponse
}

func NewServer(notifier notifier, observer observer) *Server {
	return &Server{
		notifier: notifier,
		observer: observer,
	}
}

func newListener() *getEventsListener {
	return &getEventsListener{
		events: make(chan *fgs.GetEventsResponse, 100),
	}
}

func (l *getEventsListener) Notify(res *fgs.GetEventsResponse) {
	l.events <- res
}

func (s *Server) NotifyListeners(original interface{}, processed *fgs.GetEventsResponse) {
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
func (s *Server) GetEvents(request *fgs.GetEventsRequest, server fgs.FineGuidanceSensors_GetEventsServer) error {
	return s.GetEventsWG(request, server, nil)
}

func (s *Server) GetEventsWG(request *fgs.GetEventsRequest, server fgs.FineGuidanceSensors_GetEventsServer, readyWG *sync.WaitGroup) error {
	logger.GetLogger().WithField("request", request).Debug("Received a GetEvents request")
	allowList, err := filters.BuildFilterList(context.Background(), request.AllowList, filters.Filters)
	if err != nil {
		return err
	}
	denyList, err := filters.BuildFilterList(context.Background(), request.DenyList, filters.Filters)
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
	for {
		select {
		case event := <-l.events:
			if !hubbleFilters.Apply(allowList, denyList, &v1.Event{Event: event}) {
				// Event is filtered out. Nothing to do here. Continue.
				continue
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
			return server.Context().Err()
		}
	}
}

func (s *Server) GetHealth(ctx context.Context, request *fgs.GetHealthStatusRequest) (*fgs.GetHealthStatusResponse, error) {
	logger.GetLogger().WithField("request", request).Debug("Received a GetHealth request")
	return health.GetHealth()
}

func (s *Server) ListSensors(ctx context.Context, request *fgs.ListSensorsRequest) (*fgs.ListSensorsResponse, error) {
	logger.GetLogger().Debug("Received a ListSensors request")
	var ret *fgs.ListSensorsResponse
	list, err := s.observer.ListSensors(ctx)
	if err == nil {
		sensors := make([]*fgs.SensorStatus, 0, len(*list))
		for _, s := range *list {
			sensors = append(sensors, &fgs.SensorStatus{Name: s.Name, Enabled: s.Enabled})
		}
		ret = &fgs.ListSensorsResponse{Sensors: sensors}
	}

	return ret, err
}

func (s *Server) AddTracingPolicy(ctx context.Context, req *fgs.AddTracingPolicyRequest) (*fgs.AddTracingPolicyResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received an AddTracingPolicy request")
	conf, err := config.ReadConfigYaml(req.GetYaml())
	if err != nil {
		return nil, err
	}
	if err := s.observer.AddTracingPolicy(ctx, conf.Metadata.Name, &conf.Spec); err != nil {
		return nil, err
	}
	return &fgs.AddTracingPolicyResponse{}, nil
}

func (s *Server) DelTracingPolicy(ctx context.Context, req *fgs.DeleteTracingPolicyRequest) (*fgs.DeleteTracingPolicyResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received an DeleteTracingPolicy request")
	conf, err := config.ReadConfigYaml(req.GetYaml())
	if err != nil {
		return nil, err
	}
	if err := s.observer.DelTracingPolicy(ctx, conf.Metadata.Name); err != nil {
		return nil, err
	}
	return &fgs.DeleteTracingPolicyResponse{}, nil
}
func (s *Server) RemoveSensor(ctx context.Context, req *fgs.RemoveSensorRequest) (*fgs.RemoveSensorResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a RemoveTracingPolicy request")
	if err := s.observer.RemoveSensor(ctx, req.GetName()); err != nil {
		return nil, err
	}
	return &fgs.RemoveSensorResponse{}, nil
}

func (s *Server) EnableSensor(ctx context.Context, req *fgs.EnableSensorRequest) (*fgs.EnableSensorResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a EnableSensor request")
	err := s.observer.EnableSensor(ctx, req.GetName())
	var ret *fgs.EnableSensorResponse
	if err == nil {
		ret = &fgs.EnableSensorResponse{}
	}
	return ret, err
}

func (s *Server) DisableSensor(ctx context.Context, req *fgs.DisableSensorRequest) (*fgs.DisableSensorResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a DisableSensor request")
	err := s.observer.DisableSensor(ctx, req.GetName())
	if err != nil {
		return nil, err
	}

	return &fgs.DisableSensorResponse{}, nil
}

func (s *Server) GetSensorConfig(ctx context.Context, req *fgs.GetSensorConfigRequest) (*fgs.GetSensorConfigResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a GetSensorConfig request")
	cfgval, err := s.observer.GetSensorConfig(ctx, req.GetName(), req.GetCfgkey())
	if err != nil {
		return nil, err
	}

	return &fgs.GetSensorConfigResponse{Cfgval: cfgval}, nil
}

func (s *Server) SetSensorConfig(ctx context.Context, req *fgs.SetSensorConfigRequest) (*fgs.SetSensorConfigResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a SetSensorConfig request")
	err := s.observer.SetSensorConfig(ctx, req.GetName(), req.GetCfgkey(), req.GetCfgval())
	if err != nil {
		return nil, err
	}

	return &fgs.SetSensorConfigResponse{}, nil
}
func (s *Server) GetStackTraceTree(ctx context.Context, req *fgs.GetStackTraceTreeRequest) (*fgs.GetStackTraceTreeResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a GetStackTraceTreee request")
	root, err := s.observer.GetTreeProto(ctx, req.GetName())
	if err != nil {
		return nil, err
	}

	return &fgs.GetStackTraceTreeResponse{Root: root}, nil
}

func (s *Server) GetVersion(ctx context.Context, req *fgs.GetVersionRequest) (*fgs.GetVersionResponse, error) {
	return &fgs.GetVersionResponse{Version: version.Version}, nil
}
