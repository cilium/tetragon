// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/sirupsen/logrus"
)

// facilities to extend the base sensor

type ExtensionFn func(base *sensors.Sensor) (*sensors.Sensor, error)

type extension struct {
	name string
	fn   ExtensionFn
}

var extensions []extension

func RegisterExtensionAtInit(name string, fn ExtensionFn) {
	extensions = append(extensions, extension{
		name: name,
		fn:   fn,
	})
}

func ApplyExtensions(s *sensors.Sensor) *sensors.Sensor {
	for _, ext := range extensions {
		newS, err := ext.fn(s)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"extension": ext.name,
				"error":     err,
			}).Warn("failed to apply base sensor extension")
			continue
		}
		s = newS
	}
	return s
}
