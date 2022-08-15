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

	processIdent := common.TetragonApiIdent(g, "Process")

	g.P(`// IsGetEventsResponse_Event encapulates isGetEventsResponse_Event
    type IsGetEventsResponse_Event = isGetEventsResponse_Event`)

	g.P(`// Event represents a Tetragon event
    type Event interface {
        Encapsulate() IsGetEventsResponse_Event
    }`)

	g.P(`// ProcessEvent represents a Tetragon event that has a Process field
    type ProcessEvent interface {
        Event
        SetProcess(p *` + processIdent + `)
    }`)

	g.P(`// ParentEvent represents a Tetragon event that has a Parent field
    type ParentEvent interface {
        Event
        SetParent(p * ` + processIdent + `)
    }`)

	// Generate impls
	for _, event := range events {
		g.P(`// Encapsulate implements the Event interface.
        // Returns the event wrapped by its GetEventsResponse_* type.
        func (event *` + event.GoIdent.GoName + `) Encapsulate() IsGetEventsResponse_Event {
            return &GetEventsResponse_` + event.GoIdent.GoName + `{
                ` + event.GoIdent.GoName + `: event,
            }
        }`)

		if common.IsProcessEvent(event) {
			g.P(`// SetProcess implements the ProcessEvent interface.
            // Sets the Process field of an event.
            func (event *` + event.GoIdent.GoName + `) SetProcess(p *` + processIdent + `) {
                event.Process = p
            }`)
		}

		if common.IsParentEvent(event) {
			g.P(`// SetParent implements the ParentEvent interface.
            // Sets the Parent field of an event.
            func (event *` + event.GoIdent.GoName + `) SetParent(p *` + processIdent + `) {
                event.Parent = p
            }`)
		}
	}

	return nil
}
