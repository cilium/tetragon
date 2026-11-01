// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"log/slog"
	"testing"
	"testing/synctest"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// A checker that is done stops reading its channel, while events keep coming.
// The forwarder must still take the message that unsets that channel.
func TestRunFwdUnsetsBlockedOutput(t *testing.T) {
	synctest.Test(t, func(*testing.T) {
		in := make(chan *tetragon.GetEventsResponse)
		ctl := make(chan fwdCtl)
		done := make(chan struct{})
		go func() {
			runFwd(slog.New(slog.DiscardHandler), in, ctl)
			close(done)
		}()

		ctl <- fwdCtl{cmd: fwdCmdSetForward, fwd: make(chan *tetragon.GetEventsResponse)}
		in <- &tetragon.GetEventsResponse{}
		ctl <- fwdCtl{cmd: fwdCmdSetForward}
		ctl <- fwdCtl{cmd: fwdCmdExit}
		<-done
	})
}
