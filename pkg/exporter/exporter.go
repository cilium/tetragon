// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	"context"
	"io"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/server"
	"google.golang.org/grpc/metadata"
)

type ExportEncoder interface {
	Encode(v interface{}) error
}

type Exporter struct {
	ctx         context.Context
	request     *tetragon.GetEventsRequest
	server      *server.Server
	encoder     ExportEncoder
	closer      io.Closer
	rateLimiter *ratelimit.RateLimiter
	done        chan bool
}

func NewExporter(
	ctx context.Context,
	request *tetragon.GetEventsRequest,
	server *server.Server,
	encoder ExportEncoder,
	closer io.Closer,
	rateLimiter *ratelimit.RateLimiter,
) *Exporter {
	return &Exporter{ctx, request, server, encoder, closer, rateLimiter, make(chan bool)}
}

func (e *Exporter) Start() {
	var readyWG sync.WaitGroup
	readyWG.Add(1)
	go func() {
		if err := e.server.GetEventsWG(e.request, e, e.closer, &readyWG); err != nil {
			if e.ctx.Err() == nil {
				logger.GetLogger().WithError(err).Error("Failed to start JSON exporter")
			}
		}
		e.done <- true
	}()
	readyWG.Wait()
}

func (e *Exporter) Send(event *tetragon.GetEventsResponse) error {
	if e.rateLimiter != nil && !e.rateLimiter.Allow() {
		e.rateLimiter.Drop()
		return nil
	}
	if err := e.encoder.Encode(event); err != nil {
		logger.GetLogger().WithError(err).Warning("Failed to JSON encode")
	}
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

func (e *Exporter) SendMsg(_ interface{}) error {
	return nil
}

func (e *Exporter) RecvMsg(_ interface{}) error {
	return nil
}
