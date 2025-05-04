// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

type JSONStdoutEncoder struct{}

func NewJSONStdoutEncoder() *JSONStdoutEncoder {
	return &JSONStdoutEncoder{}
}

func (e *JSONStdoutEncoder) Encode(v interface{}) error {
	logger.GetLogger().Debug("Received event for encoding")
	evt, ok := v.(*tetragon.GetEventsResponse)
	if !ok {
		logger.GetLogger().WithField("type", fmt.Sprintf("%T", v)).Warn("Expected GetEventsResponse, got different type")
		return fmt.Errorf("expected GetEventsResponse, got %T", v)
	}
	jsonBytes, err := protojson.Marshal(evt)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to marshal event to JSON")
		return nil
	}
	logger.GetLogger().Debugf("Encoded event: %s", string(jsonBytes))
	output := append([]byte("EVENT: "), jsonBytes...) // Add EVENT: prefix
	output = append(output, '\n')
	if _, err := os.Stdout.Write(output); err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to write to stdout")
		return nil
	}
	os.Stdout.Sync()
	logger.GetLogger().Debugf("Wrote JSON to stdout: %s", string(output))
	return nil
}

func (e *JSONStdoutEncoder) Close() error {
	return nil
}
