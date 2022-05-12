// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"github.com/iancoleman/strcase"
	"google.golang.org/protobuf/compiler/protogen"
)

func generateEventTypeString(g *protogen.GeneratedFile, f *protogen.File) error {
	events, err := common.GetEvents(f)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, msg := range events {
			resGoIdent := common.FgsApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", msg.GoIdent.GoName))
			typeName := strcase.ToScreamingSnake(msg.GoIdent.GoName)
			typeGoIdent := common.FgsApiIdent(g, fmt.Sprintf("EventType_%s", typeName))

			ret += `case *` + resGoIdent + `:
                return ` + typeGoIdent + `.String(), nil
            `
		}
		return ret
	}

	g.P(`// EventTypeString returns an event's type as a string
    func EventTypeString(event event) (string, error) {
        if event == nil {
            return "", ` + common.FmtErrorf(g, "Event is nil") + `
        }
        switch event.(type) {
            ` + doCases() + `
        }
        return "", ` + common.FmtErrorf(g, "Unhandled event type %T", "event") + `
	 }`)

	return nil
}

func generateResponseGetProcess(g *protogen.GeneratedFile, f *protogen.File) error {
	tetragonProcess := common.FgsApiIdent(g, "Process")
	tetragonGER := common.FgsApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetProcess gets the process field for a response if it exists
    func ResponseGetProcess(response response) *` + tetragonProcess + ` {
        if response == nil {
            return nil
        }
        switch res := response.(type) {
             case *` + tetragonGER + `:
                 return EventGetProcess(res.Event)
         }
         return nil
	 }`)

	return nil
}

func generateEventGetProcess(g *protogen.GeneratedFile, f *protogen.File) error {
	tetragonProcess := common.FgsApiIdent(g, "Process")

	events, err := common.GetEvents(f)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, msg := range events {
			if !common.IsProcessEvent(msg) {
				continue
			}

			goIdent := common.FgsApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", msg.GoIdent.GoName))

			ret += `case *` + goIdent + `:
                return ev.` + msg.GoIdent.GoName + `.Process
            `
		}
		return ret
	}

	g.P(`// EventGetProcess gets the process field for an event if it exists
    func EventGetProcess(event event) *` + tetragonProcess + ` {
        if event == nil {
            return nil
        }
        switch ev := event.(type) {
            ` + doCases() + `
        }
        return nil
    }`)

	return nil
}

func generateResponseGetParent(g *protogen.GeneratedFile, f *protogen.File) error {
	tetragonProcess := common.FgsApiIdent(g, "Process")
	tetragonGER := common.FgsApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetParent gets the parent field for a response if it exists
    func ResponseGetParent(response response) *` + tetragonProcess + ` {
        if response == nil {
            return nil
        }
        switch res := response.(type) {
             case *` + tetragonGER + `:
                 return EventGetParent(res.Event)
         }
         return nil
	 }`)

	return nil
}

func generateEventGetParent(g *protogen.GeneratedFile, f *protogen.File) error {
	tetragonProcess := common.FgsApiIdent(g, "Process")

	events, err := common.GetEvents(f)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, msg := range events {
			if !common.IsParentEvent(msg) {
				continue
			}

			goIdent := common.FgsApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", msg.GoIdent.GoName))

			ret += `case *` + goIdent + `:
                return ev.` + msg.GoIdent.GoName + `.Parent
            `
		}
		return ret
	}

	g.P(`// EventGetParent gets the parent field for an event if it exists
    func EventGetParent(event event) *` + tetragonProcess + ` {
        if event == nil {
            return nil
        }
        switch ev := event.(type) {
            ` + doCases() + `
        }
        return nil
    }`)

	return nil
}

// Generate generates boilerplate helpers
func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewGeneratedFile(gen, f, "helpers")

	g.P(`type event interface {
        // Represents a generic Tetragon event
    }`)

	g.P(`type response interface {
        // Represents a generic Tetragon gRPC response
    }`)

	if err := generateEventTypeString(g, f); err != nil {
		return err
	}

	if err := generateEventGetProcess(g, f); err != nil {
		return err
	}

	if err := generateResponseGetProcess(g, f); err != nil {
		return err
	}

	if err := generateEventGetParent(g, f); err != nil {
		return err
	}

	if err := generateResponseGetParent(g, f); err != nil {
		return err
	}

	return nil
}
