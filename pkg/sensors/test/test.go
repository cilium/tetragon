// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package test

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/tetragon/pkg/api/ops"
	api "github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/observer"
)

func init() {
	AddTest()
}
func AddTest() {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TEST, handleTest)
}

func msgToTestUnix(m *api.MsgTestEvent) *api.MsgTestEventUnix {
	return m
}

func handleTest(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgTestEvent{}
	if err := binary.Read(r, binary.LittleEndian, &m); err != nil {
		return nil, err
	}
	msgUnix := msgToTestUnix(&m)
	return []observer.Event{msgUnix}, nil
}
