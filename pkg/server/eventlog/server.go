// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventlog

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/option"
)

type Params struct {
	MaxSize          *int32
	RotationInterval *time.Duration
	MaxBackups       *int32
}

type eventLogParamsSetter interface {
	SetLogParams(params Params) error
}

type Server struct {
	logParamsSetter []eventLogParamsSetter

	tetragon.GetEventLogParamsResponse

	tetragon.UnimplementedEventLogServiceServer

	mu sync.Mutex
}

func New(setters ...eventLogParamsSetter) *Server {
	return &Server{
		logParamsSetter: setters,
		GetEventLogParamsResponse: tetragon.GetEventLogParamsResponse{
			MaxSize:          int32(option.Config.ExportFileMaxSizeMB),
			RotationInterval: option.Config.ExportFileRotationInterval.String(),
			MaxBackups:       int32(option.Config.ExportFileMaxBackups),
		},
		UnimplementedEventLogServiceServer: tetragon.UnimplementedEventLogServiceServer{},
	}
}

func (s *Server) SetEventLogParams(_ context.Context, req *tetragon.SetEventLogParamsRequest) (*tetragon.SetEventLogParamsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	logParams := Params{
		MaxSize:    req.MaxSize,
		MaxBackups: req.MaxBackups,
	}

	if req.RotationInterval != nil {
		d, err := time.ParseDuration(*req.RotationInterval)
		if err != nil {
			return nil, err
		}
		logParams.RotationInterval = &d
	}

	for _, setter := range s.logParamsSetter {
		if err := setter.SetLogParams(logParams); err != nil {
			return nil, err
		}
	}

	// Update server params
	if req.MaxSize != nil {
		s.MaxSize = *req.MaxSize
	}
	if req.MaxBackups != nil {
		s.MaxBackups = *req.MaxBackups
	}
	if req.RotationInterval != nil {
		s.RotationInterval = *req.RotationInterval
	}

	return &tetragon.SetEventLogParamsResponse{}, nil
}

func (s *Server) GetEventLogParams(_ context.Context, _ *tetragon.GetEventLogParamsRequest) (*tetragon.GetEventLogParamsResponse, error) {
	return &s.GetEventLogParamsResponse, nil
}
