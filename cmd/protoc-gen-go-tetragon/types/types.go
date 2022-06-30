// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package types

import (
	"path/filepath"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

func Generate(gen *protogen.Plugin, files []*protogen.File) error {
	g := common.NewFile(gen, files[0], "", filepath.Base(common.TetragonApiPackageName), "types")

	events, err := common.GetEvents(files)
	if err != nil {
		return err
	}

	g.P(`// Event represents a Tetragon event
    type Event interface {
        __isEvent()
    }`)

	// Generate impls
	for _, event := range events {
		g.P(`func (event *` + event.GoIdent.GoName + `) __isEvent() {}`)
	}

	g.P(`// ResponseEvent represents a Tetragon GetEventsResponse inner type
    type ResponseEvent isGetEventsResponse_Event`)

	return nil
}
