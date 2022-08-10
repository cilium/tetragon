// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package readyapi

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

type MsgTETRAGONReady struct{}

func (msg *MsgTETRAGONReady) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unsupported cache event MsgTETRAGONReady")
}

func (msg *MsgTETRAGONReady) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return fmt.Errorf("Unsupported cache retry event MsgTETRAGONReady")
}

func (msg *MsgTETRAGONReady) HandleMessage() *tetragon.GetEventsResponse {
	return nil
}
