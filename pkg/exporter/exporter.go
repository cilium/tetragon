// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/lumberjack/v2"
	"google.golang.org/grpc/metadata"

	"github.com/cilium/tetragon/pkg/server/eventlog"

	"github.com/cilium/tetragon/pkg/option"

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
	ctx              context.Context
	request          *tetragon.GetEventsRequest
	server           *server.Server
	encoder          ExportEncoder
	closer           io.Closer
	rateLimiter      *ratelimit.RateLimiter
	rotateTimer      *time.Timer
	logFile          string
	logsDir          string
	rotationInterval time.Duration
}

func NewExporter(
	ctx context.Context,
	request *tetragon.GetEventsRequest,
	server *server.Server,
	encoder ExportEncoder,
	closer io.Closer,
	rateLimiter *ratelimit.RateLimiter,
) (*Exporter, error) {
	logFile := filepath.Base(option.Config.ExportFilename)
	logsDir, err := filepath.Abs(filepath.Dir(filepath.Clean(option.Config.ExportFilename)))
	if err != nil {
		logger.GetLogger().Warn(fmt.Sprintf("Failed to get absolute path of exported JSON logs '%s'", option.Config.ExportFilename), logfields.Error, err)
		// Do not fail; we let lumberjack handle this. We want to
		// log the rotate logs operation.
		logsDir = filepath.Dir(option.Config.ExportFilename)
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return nil, fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	}

	e := &Exporter{
		ctx:              ctx,
		request:          request,
		server:           server,
		encoder:          encoder,
		closer:           closer,
		rateLimiter:      rateLimiter,
		logFile:          logFile,
		logsDir:          logsDir,
		rotationInterval: option.Config.ExportFileRotationInterval,
	}
	return e, nil
}

func (e *Exporter) Start() error {
	// Start the rotation timer if needed
	if e.rotationInterval > 0 {
		_, ok := e.closer.(*lumberjack.Logger)
		if !ok {
			return fmt.Errorf("writer must be of type lumberjack.Logger but got %T", e.closer)
		}
		e.rotateTimer = time.AfterFunc(e.rotationInterval, e.rotate)
	}

	// Start the events processor
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

func (e *Exporter) rotate() {
	// Rotate is only called when writer is a lumberjack logger; no need to check.
	writer := e.closer.(*lumberjack.Logger)
	logger.GetLogger().Info("Rotating JSON logs export", "file", e.logFile, "directory", e.logsDir)
	if rotationErr := writer.Rotate(); rotationErr != nil {
		logger.GetLogger().Warn("Failed to rotate JSON export file", "file", option.Config.ExportFilename, logfields.Error, rotationErr)
	}
	e.rotateTimer = time.AfterFunc(e.rotationInterval, e.rotate)
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

func (e *Exporter) SetLogParams(params eventlog.Params) error {
	writer, ok := e.closer.(*lumberjack.Logger)
	if !ok {
		return errors.New("exporter does not support setting log params")
	}

	logger.GetLogger().Info("Updating exporter params", "params", params)

	if params.MaxSize != nil {
		writer.MaxSize = int(*params.MaxSize)
	}

	if params.MaxBackups != nil {
		writer.MaxBackups = int(*params.MaxBackups)
	}

	if params.RotationInterval != nil {
		if e.rotateTimer != nil {
			e.rotateTimer.Stop()
		}
		e.rotationInterval = *params.RotationInterval
		e.rotateTimer = time.AfterFunc(
			e.rotationInterval,
			e.rotate,
		)
	}

	return nil
}
