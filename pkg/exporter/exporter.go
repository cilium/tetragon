// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"fmt"
	"io"
	"sync"

	"google.golang.org/grpc/metadata"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/server"
)

type ExportEncoder interface {
	Encode(v any) error
}

type Exporter struct {
	ctx         context.Context
	request     *tetragon.GetEventsRequest
	server      *server.Server
	encoder     ExportEncoder
	closer      io.Closer
	rateLimiter *ratelimit.RateLimiter
}

func NewExporter(
	ctx context.Context,
	request *tetragon.GetEventsRequest,
	server *server.Server,
	encoder ExportEncoder,
	closer io.Closer,
	rateLimiter *ratelimit.RateLimiter,
) *Exporter {
	return &Exporter{ctx, request, server, encoder, closer, rateLimiter}
}

func (e *Exporter) Start() error {
	var readyWG sync.WaitGroup
	var exporterStartErr error
	readyWG.Add(1)
	go func() {
		if err := e.server.GetEventsWG(e.request, e, e.closer, &readyWG); err != nil {
			exporterStartErr = fmt.Errorf("error starting JSON exporter: %w", err)
		}
	}()
	readyWG.Wait()
	return exporterStartErr
}

func (e *Exporter) Send(event *tetragon.GetEventsResponse) error {
	if e.rateLimiter != nil && !e.rateLimiter.Allow() {
		e.rateLimiter.Drop()
		rateLimitDropped.Inc()
		return nil
	}

	if err := e.encoder.Encode(event); err != nil {
		logger.GetLogger().Warn("Failed to JSON encode", logfields.Error, err)
	}
	eventsExportedTotal.Inc()
	eventsExportTimestamp.Set(float64(event.GetTime().GetSeconds()))
	return nil
}

func (e *Exporter) SetHeader(metadata.MD) error {
	return nil
}

func (e *Exporter) SendHeader(metadata.MD) error {
	return nil
}

func (e *Exporter) SetTrailer(metadata.MD) {
}

func (e *Exporter) Context() context.Context {
	return e.ctx
}

func (e *Exporter) SendMsg(_ any) error {
	return nil
}

func (e *Exporter) RecvMsg(_ any) error {
	return nil
}
