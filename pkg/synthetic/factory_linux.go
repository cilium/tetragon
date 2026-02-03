// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/logger"
)

// NewReadingObserverFromFile creates a ReadingObserver that reads from the specified file.
// The file will be closed when the context is cancelled.
func NewReadingObserverFromFile(ctx context.Context, path string, log logger.FieldLogger) (*ReadingObserver, error) {
	f, err := openSourceFile(path)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() {
		f.Close()
	})
	return NewReadingObserver(f, Serializer{}, log), nil
}

// NewWritingListenerToFile creates a WritingListener that writes to the specified file.
// If the file already exists, it will be renamed with a timestamp prefix.
// The file will be closed when the context is cancelled.
func NewWritingListenerToFile(ctx context.Context, path string, log logger.FieldLogger, opts ...Option) (*WritingListener, error) {
	f, err := openLogFile(path)
	if err != nil {
		return nil, err
	}
	bufWriter := bufio.NewWriter(f)
	context.AfterFunc(ctx, func() {
		bufWriter.Flush()
		f.Close()
	})
	return NewWritingListener(bufWriter, Serializer{}, log, opts...), nil
}

// openSourceFile opens a file for reading synthetic events.
func openSourceFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open synthetic events source: %w", err)
	}
	return f, nil
}

// openLogFile opens a file for writing synthetic events.
// If the file already exists, it will be renamed with a timestamp prefix.
func openLogFile(path string) (*os.File, error) {
	// If file exists, rename it with modification time prefix
	if info, err := os.Stat(path); err == nil {
		modTime := info.ModTime().Format("2006-01-02_15-04-05")
		dir := filepath.Dir(path)
		base := filepath.Base(path)
		newName := filepath.Join(dir, modTime+"_"+base)
		if err := os.Rename(path, newName); err != nil {
			return nil, fmt.Errorf("failed to rename existing synthetic events file: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open synthetic events file: %w", err)
	}
	return f, nil
}
