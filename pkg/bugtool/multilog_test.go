// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/cilium/tetragon/pkg/logger"
)

func TestMultiLog(t *testing.T) {

	removeTimestamp := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{} // Remove the "time" key
		}
		return a
	}

	buff1 := new(bytes.Buffer)
	log1 := slog.New(slog.NewTextHandler(buff1, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: removeTimestamp,
	}))

	buff2 := new(bytes.Buffer)
	log2 := slog.New(slog.NewTextHandler(buff2, &slog.HandlerOptions{
		Level:       slog.LevelWarn,
		ReplaceAttr: removeTimestamp,
	}))

	multiLog := MultiLog{
		Logs: []logger.FieldLogger{log1, log2},
	}

	multiLog.Info("foo")
	multiLog.Warn("bar")
	expected1 := "level=INFO msg=foo\nlevel=WARN msg=bar\n"
	if buff1.String() != expected1 {
		t.Errorf("Expected:\n%s\nbut got:\n%s\n", expected1, buff1.String())
	}

	expected2 := "level=WARN msg=bar\n"
	if buff2.String() != expected2 {
		t.Errorf("Expected:\n%s\nbut got:\n%s\n", expected2, buff2.String())
	}

	t.Log("Success")
}
