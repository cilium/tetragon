// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

// EventListener implements observertypes.Listener and writes all received events
// to a JSON lines file for later replay.
type EventListener struct {
	file *os.File
	mu   sync.Mutex
	log  logger.FieldLogger
}

// NewEventListener creates a new EventListener that writes events to the specified path.
// If the file already exists, it will be renamed with a timestamp prefix.
func NewEventListener(path string) (*EventListener, error) {
	// If file exists, rename it with modification time prefix
	if info, err := os.Stat(path); err == nil {
		modTime := info.ModTime().Format("2006-01-02_15-04-05")
		dir := filepath.Dir(path)
		base := filepath.Base(path)
		newName := filepath.Join(dir, modTime+"_"+base)
		if err := os.Rename(path, newName); err != nil {
			return nil, fmt.Errorf("failed to rename existing log file: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open synthetic events file: %w", err)
	}

	return &EventListener{
		file: f,
		log:  logger.GetLogger(),
	}, nil
}

// Notify implements observertypes.Listener.Notify.
// It serializes the event to JSON and writes it to the file.
func (l *EventListener) Notify(msg notify.Message) error {
	typeName := reflect.TypeOf(msg).String()

	eventBytes, err := json.Marshal(msg)
	if err != nil {
		l.log.Warn("Failed to marshal event for synthetic logging", "type", typeName, "error", err)
		return nil // Don't fail the listener for marshal errors
	}

	synEvent := Event{
		Type:  typeName,
		Event: eventBytes,
	}

	logBytes, err := json.Marshal(synEvent)
	if err != nil {
		l.log.Warn("Failed to marshal synthetic event wrapper", "type", typeName, "error", err)
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		_, err = l.file.Write(append(logBytes, '\n'))
		if err != nil {
			l.log.Warn("Failed to write synthetic event", "error", err)
		}
	}

	return nil
}

// Close implements observertypes.Listener.Close.
func (l *EventListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
