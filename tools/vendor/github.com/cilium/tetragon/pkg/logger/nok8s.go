// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package logger

import (
	"log/slog"
)

func initializeKLog(logger *slog.Logger) error {
	return nil
}
