// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package readyapi

import "github.com/cilium/tetragon/api/v1/tetragon"

type MsgTETRAGONReady struct{}

func (msg *MsgTETRAGONReady) HandleMessage() *tetragon.GetEventsResponse {
	return nil
}
