// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"sigs.k8s.io/yaml"
)

var defaultReloadInterval = 5 * time.Second

type reloadCb func(hash uint64, spec Spec)

type Handler struct {
	path     string
	ticker   *time.Ticker
	stop     chan bool
	onReload reloadCb
	hash     uint64
}

func NewConfig(path string, interval time.Duration,
	onReload reloadCb) *Handler {

	if interval == 0 {
		interval = defaultReloadInterval
	}

	handler := &Handler{
		path:     path,
		onReload: onReload,
	}

	handler.reload()
	handler.ticker = time.NewTicker(interval)
	handler.stop = make(chan bool)

	go func() {
		for {
			select {
			case <-handler.stop:
				return
			case <-handler.ticker.C:
				handler.reload()
			}
		}
	}()

	return handler
}

func (h *Handler) reload() {
	config, hash, err := h.readConfig()
	if hash == h.hash {
		return
	}
	if err == nil {
		h.onReload(hash, *config)
	} else {
		logger.GetLogger().WithError(err).
			WithField("path", h.path).
			WithField("hash", hash).
			Warn("Failed to read config file")
	}
	h.hash = hash
}

func (h *Handler) Stop() {
	if h.ticker != nil {
		h.ticker.Stop()
	}
	h.stop <- true
}

func (h *Handler) readConfig() (*Spec, uint64, error) {
	config := &Spec{}

	yamlFile, err := os.ReadFile(h.path)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot read file '%s' %w", h.path, err)
	}
	hash := calculateHash(yamlFile)
	if err := yaml.Unmarshal(yamlFile, config); err != nil {
		return nil, hash, fmt.Errorf("cannot parse yaml %w", err)
	}
	return config, hash, nil
}

func calculateHash(file []byte) uint64 {
	sum := md5.Sum(file)
	return binary.LittleEndian.Uint64(sum[0:16])
}
