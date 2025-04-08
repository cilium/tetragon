// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

// Generate generates boilerplate code for the eventcheckers
func Generate(gen *protogen.Plugin, files []*protogen.File) error {
	// files[0] is used for the prefix to the generated filename. The
	// generated files will be in pkg tetragon so its not important
	// from packaging side and any prefix will work fine we just pick
	// the first file arbitrarily.
	g := common.NewCodegenFile(gen, files[0], "eventchecker")
	yaml := common.NewCodegenFile(gen, files[0], "eventchecker/yaml")

	if err := generateEventCheckerConf(yaml); err != nil {
		return err
	}

	if err := generateEventCheckerSpec(yaml, files); err != nil {
		return err
	}

	if err := generateMultiEventCheckerSpec(yaml); err != nil {
		return err
	}

	if err := generateMultiEventCheckers(g); err != nil {
		return err
	}

	if err := generateEventToChecker(g, files); err != nil {
		return err
	}

	if err := generateLogPrefix(g); err != nil {
		return err
	}

	if err := generateInterfaces(g); err != nil {
		return err
	}

	if err := generateEventFromResponse(g, files); err != nil {
		return err
	}

	if err := generateEventCheckers(g, files); err != nil {
		return err
	}

	if err := generateFieldCheckers(g, files); err != nil {
		return err
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := generateEnumCheckers(g, files); err != nil {
		return err
	}

	return nil
}

func generateEventToChecker(g *protogen.GeneratedFile, f []*protogen.File) error {
	events, err := getEvents(f)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, msg := range events {
			msgIdent := common.TetragonApiIdent(g, msg.GoIdent.GoName)
			ret += `case *` + msgIdent + `:
            return New` + msg.checkerName(g) + `("").From` + msg.GoIdent.GoName + `(ev), nil
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

func generateLogPrefix(g *protogen.GeneratedFile) error {
	g.P(`// CheckerLogPrefix is a helper that outputs the log prefix for an event checker,
    // which is a combination of the checker type and the checker name if applicable.
    func CheckerLogPrefix(checker interface{ GetCheckerType() string }) string {
        type_ := checker.GetCheckerType()

        if withName, ok := checker.(interface{ GetCheckerName() string }); ok {
            name := withName.GetCheckerName()
            if len(name) > 0 {
                return ` + common.FmtSprintf(g, "%s/%s", "type_", "name") + `
            }
        }

        return type_
    }`)

	return nil
}

func generateInterfaces(g *protogen.GeneratedFile) error {
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

func generateEventFromResponse(g *protogen.GeneratedFile, f []*protogen.File) error {
	events, err := getEvents(f)
	if err != nil {
		return err
	}

	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

	g.P(`// EventFromResponse coerces an event from a Tetragon gRPC response
    func EventFromResponse(response *` + tetragonGER + `) (Event, error) {
        switch ev := response.Event.(type) {`)
	for _, event := range events {
		g.P(`case *` + common.TetragonApiIdent(g, "GetEventsResponse_"+event.GoIdent.GoName) + `:
            return ev.` + event.GoIdent.GoName + `, nil`)
	}
	g.P(`
        default:
            return nil, ` + common.FmtErrorf(g, "Unknown event type %T", "response.Event") + `
        }
    }`)

	return nil
}

func generateEventCheckers(g *protogen.GeneratedFile, f []*protogen.File) error {
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

func generateFieldCheckers(g *protogen.GeneratedFile, f []*protogen.File) error {
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

func generateEnumCheckers(g *protogen.GeneratedFile, f []*protogen.File) error {
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
func getEvents(files []*protogen.File) ([]*CheckedMessage, error) {
	if len(eventsCache) != 0 {
		return eventsCache, nil
	}

	rawEvents, err := common.GetEvents(files)
	if err != nil {
		return nil, err
	}

	for _, rawEvent := range rawEvents {
		eventsCache = append(eventsCache, (*CheckedMessage)(rawEvent))
	}
	return eventsCache, nil
}

var fieldsCache []*CheckedMessage

// getFields is a thin wrapper around common.GetFields produces a list of messages wrapped
// by CheckedMessage.
func getFields(files []*protogen.File) ([]*CheckedMessage, error) {
	if len(fieldsCache) != 0 {
		return fieldsCache, nil
	}

	rawFields, err := common.GetFields(files)
	if err != nil {
		return nil, err
	}

	for _, rawField := range rawFields {
		fieldsCache = append(fieldsCache, (*CheckedMessage)(rawField))
	}

	return fieldsCache, nil
}

var enumsCache []*Enum

// getEnums is a thin wrapper around common.GetEnums produces a list of messages wrapped
// by Enum.
func getEnums(files []*protogen.File) ([]*Enum, error) {
	if len(enumsCache) != 0 {
		return enumsCache, nil
	}

	rawEnums, err := common.GetEnums(files)
	if err != nil {
		return nil, err
	}

	for _, rawEnum := range rawEnums {
		enumsCache = append(enumsCache, (*Enum)(rawEnum))
	}
	return enumsCache, nil
}
