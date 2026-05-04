// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventlog

import (
	"context"
	"errors"
	"reflect"
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
	// SetLogParams is meant to be only called by the eventlog grpc service.
	// DO NOT CALL THIS METHOD DIRECTLY.
	SetLogParams(params Params) error
}

type Server struct {
	logParamsSetter []eventLogParamsSetter

	tetragon.GetEventLogParamsResponse

	tetragon.UnimplementedEventLogServiceServer

	mu sync.Mutex
}

// Helper to detect typed nils
func isNil(i any) bool {
	v := reflect.ValueOf(i)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return true
	}
	return false
}

func New(setters ...eventLogParamsSetter) *Server {
	var validSetters []eventLogParamsSetter

	for _, s := range setters {
		// Check if the interface itself is nil OR if it contains a nil pointer
		if s != nil && !isNil(s) {
			validSetters = append(validSetters, s)
		}
	}
	return &Server{
		logParamsSetter: validSetters,
		GetEventLogParamsResponse: tetragon.GetEventLogParamsResponse{
			MaxSize:          int32(option.Config.ExportFileMaxSizeMB),
			RotationInterval: option.Config.ExportFileRotationInterval.String(),
			MaxBackups:       int32(option.Config.ExportFileMaxBackups),
		},
		UnimplementedEventLogServiceServer: tetragon.UnimplementedEventLogServiceServer{},
	}
}

func (s *Server) SetEventLogParams(_ context.Context, req *tetragon.SetEventLogParamsRequest) (*tetragon.SetEventLogParamsResponse, error) {
	if len(s.logParamsSetter) == 0 {
		return nil, errors.New("no log params setters available")
	}

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
	if len(s.logParamsSetter) == 0 {
		return nil, errors.New("no log params setters available")
	}
	return &s.GetEventLogParamsResponse, nil
}
