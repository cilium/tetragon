// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package timer

import (
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/stretchr/testify/assert"
)

var (
	count = 0
)

func TestTimer(t *testing.T) {
	assert := assert.New(t)
	timer1 := NewPeriodicTimer("Test 1", Worker, true)
	timer1.Start(time.Duration(100) * time.Millisecond)
	time.Sleep(time.Duration(550) * time.Millisecond)
	timer1.Stop()
	assert.Equal(count, 5, "Tests simple timer (100ms interval)")
	timer1.Start(time.Duration(1000) * time.Millisecond)
	time.Sleep(time.Duration(1500) * time.Millisecond)
	assert.Equal(count, 6, "Tests simple timer (1000ms interval)")
	timer1.Start(time.Duration(200) * time.Millisecond)
	time.Sleep(time.Duration(300) * time.Millisecond)
	timer1.Stop()
	assert.Equal(count, 7, "Tests restart of timer")
}

func Worker() {
	count++
	logger.GetLogger().WithField("count", count).Info("Counting")
}
