// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

// Generate generates boilerplate code for the eventcheckers
func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewCodegenFile(gen, f, "eventchecker")
	yaml := common.NewCodegenFile(gen, f, "eventchecker/yaml")

	if err := generateEventCheckerConf(yaml, f); err != nil {
		return err
	}

	if err := generateEventCheckerSpec(yaml, f); err != nil {
		return err
	}

	if err := generateMultiEventCheckerSpec(yaml, f); err != nil {
		return err
	}

	if err := generateMultiEventCheckers(g, f); err != nil {
		return err
	}

	if err := generateEventToChecker(g, f); err != nil {
		return err
	}

	if err := generateInterfaces(g, f); err != nil {
		return err
	}

	if err := generateEventFromResponse(g, f); err != nil {
		return err
	}

	if err := generateEventCheckers(g, f); err != nil {
		return err
	}

	if err := generateFieldCheckers(g, f); err != nil {
		return err
	}

	if err := generateEnumCheckers(g, f); err != nil {
		return err
	}

	return nil
}

func generateEventToChecker(g *protogen.GeneratedFile, f *protogen.File) error {
	events, err := getEvents(f)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, msg := range events {
			msgIdent := common.TetragonApiIdent(g, msg.GoIdent.GoName)
			ret += `case *` + msgIdent + `:
            return New` + msg.checkerName(g) + `().From` + msg.GoIdent.GoName + `(ev), nil
            `
		}
		return ret
	}

	g.P(`// CheckerFromEvent converts an event into an EventChecker
    func CheckerFromEvent(event Event) (EventChecker, error) {
        switch ev := event.(type) {
        ` + doCases() + `
        default:
            return nil, ` + common.FmtErrorf(g, "Unhandled event type %T", "event") + `
        }
    }`)

	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")
	g.P(`// ResponseToChecker converts a gRPC response into an EventChecker
    func CheckerFromResponse(response *` + tetragonGER + `) (EventChecker, error) {
        event, err := EventFromResponse(response)
        if err != nil {
            return nil, err
        }
        return CheckerFromEvent(event)
    }`)

	return nil
}

func generateInterfaces(g *protogen.GeneratedFile, f *protogen.File) error {
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")
	tetragonEvent := common.TetragonApiIdent(g, "Event")

	g.P(`// Event is an empty interface used for events like ProcessExec, etc.
    type Event ` + tetragonEvent)

	g.P(`// EventChecker is an interface for checking a Tetragon event
    type EventChecker interface {
        // CheckEvent checks a single event
        CheckEvent(Event) error
        // CheckEvent checks a single gRPC response
        CheckResponse(*` + tetragonGER + `) error
    }`)

	return nil
}

func generateEventFromResponse(g *protogen.GeneratedFile, f *protogen.File) error {
	events, err := getEvents(f)
	if err != nil {
		return err
	}

	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

	g.P(`// EventFromResponse coerces an event from a Tetragon gRPC response
    func EventFromResponse(response *` + tetragonGER + `) (Event, error) {
        switch ev := response.Event.(type) {`)
	for _, event := range events {
		g.P(`case *` + common.TetragonApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", event.GoIdent.GoName)) + `:
            return ev.` + event.GoIdent.GoName + `, nil`)
	}
	g.P(`
        default:
            return nil, ` + common.FmtErrorf(g, "Unknown event type %T", "response.Event") + `
        }
    }`)

	return nil
}

func generateEventCheckers(g *protogen.GeneratedFile, f *protogen.File) error {
	events, err := getEvents(f)
	if err != nil {
		return err
	}

	for _, event := range events {
		if err := event.Generate(g, true); err != nil {
			return err
		}
	}

	return nil
}

func generateFieldCheckers(g *protogen.GeneratedFile, f *protogen.File) error {
	fields, err := getFields(f)
	if err != nil {
		return err
	}

	for _, field := range fields {
		if err := field.Generate(g, false); err != nil {
			return err
		}
	}

	return nil
}

func generateEnumCheckers(g *protogen.GeneratedFile, f *protogen.File) error {
	enums, err := getEnums(f)
	if err != nil {
		return err
	}

	for _, enum := range enums {
		if err := enum.Generate(g); err != nil {
			return err
		}
	}

	return nil
}

var eventsCache []*CheckedMessage

// getEvents is a thin wrapper around common.GetEvents produces a list of messages wrapped
// by CheckedMessage.
func getEvents(f *protogen.File) ([]*CheckedMessage, error) {
	if len(eventsCache) == 0 {
		rawEvents, err := common.GetEvents(f)
		if err != nil {
			return nil, err
		}

		for _, rawEvent := range rawEvents {
			eventsCache = append(eventsCache, (*CheckedMessage)(rawEvent))
		}
	}

	return eventsCache, nil
}

var fieldsCache []*CheckedMessage

// getFields is a thin wrapper around common.GetFields produces a list of messages wrapped
// by CheckedMessage.
func getFields(f *protogen.File) ([]*CheckedMessage, error) {
	if len(fieldsCache) == 0 {
		rawFields, err := common.GetFields(f)
		if err != nil {
			return nil, err
		}

		for _, rawField := range rawFields {
			fieldsCache = append(fieldsCache, (*CheckedMessage)(rawField))
		}
	}

	return fieldsCache, nil
}

var enumsCache []*Enum

// getEnums is a thin wrapper around common.GetEnums produces a list of messages wrapped
// by Enum.
func getEnums(f *protogen.File) ([]*Enum, error) {
	if len(enumsCache) == 0 {
		rawEnums, err := common.GetEnums(f)
		if err != nil {
			return nil, err
		}

		for _, rawEnum := range rawEnums {
			enumsCache = append(enumsCache, (*Enum)(rawEnum))
		}
	}

	return enumsCache, nil
}
