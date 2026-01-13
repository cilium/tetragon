// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"encoding/json"

	"github.com/cilium/tetragon/pkg/api/processapi"
	exec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/exec/userinfo"
)

func RegisterSyntheticEvents() {
	observer.RegisterSyntheticUnmarshaler("Execve", func(data json.RawMessage) (notify.Message, error) {
		var input struct {
			Unix struct {
				Msg     processapi.MsgExecveEvent `json:"Msg"`
				Process processapi.MsgProcess     `json:"Process"`
			} `json:"Unix"`
		}
		if err := json.Unmarshal(data, &input); err != nil {
			return nil, err
		}

		unixEvent := msgToExecveUnix(&input.Unix.Msg)
		unixEvent.Unix.Process = input.Unix.Process

		// Resolve user info (UID -> Username, etc.)
		if err := userinfo.MsgToExecveAccountUnix(unixEvent.Unix); err != nil {
			// We log but don't fail, matching handleExecve behavior
		}

		// In a real event, we resolve Kube info here.
		// We attempt it, but it might be empty if the synthetic event doesn't have valid cgroup info for this host.
		unixEvent.Unix.Kube = msgToExecveKubeUnix(&input.Unix.Msg, process.GetExecID(&unixEvent.Unix.Process), unixEvent.Unix.Process.Filename)

		return unixEvent, nil
	})

	observer.RegisterSyntheticUnmarshaler("Exit", func(data json.RawMessage) (notify.Message, error) {
		var event processapi.MsgExitEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		return msgToExitUnix(&event), nil
	})

	observer.RegisterSyntheticUnmarshaler("Clone", func(data json.RawMessage) (notify.Message, error) {
		var event processapi.MsgCloneEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		// Logic from handleClone
		return &exec.MsgCloneEventUnix{MsgCloneEvent: event}, nil
	})

	observer.RegisterSyntheticUnmarshaler("Cgroup", func(data json.RawMessage) (notify.Message, error) {
		var event processapi.MsgCgroupEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		// Logic from handleCgroupEvent
		return &exec.MsgCgroupEventUnix{MsgCgroupEvent: event}, nil
	})
}
