// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package readyapi

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

type MsgTetragonReady struct{}

func (msg *MsgTetragonReady) Notify() bool {
	return false
}

func (msg *MsgTetragonReady) HandleMessage() *tetragon.GetEventsResponse {
	return nil
}

func (msg *MsgTetragonReady) Cast(o interface{}) notify.Message {
	return &MsgTetragonReady{}
}
