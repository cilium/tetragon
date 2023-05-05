// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package readyapi

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

type MsgTetragonReady struct{}

func (msg *MsgTetragonReady) Notify() bool {
	return false
}

func (msg *MsgTetragonReady) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unsupported cache event MsgTetragonReady")
}

func (msg *MsgTetragonReady) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return fmt.Errorf("Unsupported cache retry event MsgTetragonReady")
}

func (msg *MsgTetragonReady) HandleMessage() *tetragon.GetEventsResponse {
	return nil
}

func (msg *MsgTetragonReady) Cast(_ interface{}) notify.Message {
	return &MsgTetragonReady{}
}
