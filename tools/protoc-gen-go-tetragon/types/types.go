// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package types

import (
	"path/filepath"

	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/common"
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

	g.P(`// AncestorEvent represents a Tetragon event that has an Ancestor field
    type AncestorEvent interface {
        Event
        SetAncestors(ps []* ` + processIdent + `)
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

		if common.IsAncestorsEvent(event) {
			g.P(`// SetAncestors implements the AncestorEvent interface.
            // Sets the Ancestor field of an event.
            func (event *` + event.GoIdent.GoName + `) SetAncestors(ps []*` + processIdent + `) {
                event.Ancestors = ps
            }`)
		}
	}

	// Generate UnwrapGetEventsResponse
	g.P(`// UnwrapGetEventsResponse gets the inner event type from a GetEventsResponse
    func UnwrapGetEventsResponse(response *GetEventsResponse) interface{} {
        event := response.GetEvent()
        if event == nil {
            return nil
        }
        switch ev := event.(type) {`)
	for _, event := range events {
		g.P(`case *GetEventsResponse_` + event.GoIdent.GoName + `:
            return ev.` + event.GoIdent.GoName)
	}
	g.P(`}
        return nil
    }`)

	fdIdent := common.GoIdent(g, "google.golang.org/protobuf/reflect/protoreflect", "FieldDescriptor")
	valIdent := common.GoIdent(g, "google.golang.org/protobuf/reflect/protoreflect", "Value")

	g.P(`// ResponseIsType checks whether the GetEventsResponse is of the type specified by this EventType
    func (type_ EventType) ResponseIsType(response *GetEventsResponse) bool {
        if response == nil {
            return false
        }

        eventProtoNum := response.EventType()
        return eventProtoNum == type_
    }
    `)

	g.P(`// EventIsType checks whether the Event is of the type specified by this EventType
    func (type_ EventType) EventIsType(event Event) bool {
        if event == nil {
            return false
        }

        eventWrapper := event.Encapsulate()
        ger := GetEventsResponse {
            Event: eventWrapper,
        }

        return type_.ResponseIsType(&ger)
    }
    `)

	g.P(`// EventType gets the EventType for a GetEventsResponse
    func (response *GetEventsResponse) EventType() EventType {
        eventProtoNum := EventType_UNDEF

        if response == nil {
            return eventProtoNum
        }

        // Find the protobuf number for the set oneof field, if it exists.
        // Later on, we use this number to figure out if the set oneof field matches
        // our expected event type.
        rft := response.ProtoReflect()
        rft.Range(func(eventDesc ` + fdIdent + `, v ` + valIdent + `) bool {
            if eventDesc.ContainingOneof() == nil || !rft.Has(eventDesc) {
                return true
            }

            eventProtoNum = EventType(eventDesc.Number())
            return false
        })

        return eventProtoNum
    }
    `)

	return nil
}
