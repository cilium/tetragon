// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

func generateEventTypeString(g *protogen.GeneratedFile, f *protogen.File) error {
	oneofs, err := common.GetEventsResponseOneofs(f)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, oneof := range oneofs {
			resGoIdent := common.TetragonApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", oneof.TypeName))
			typeGoIdent := common.TetragonApiIdent(g, fmt.Sprintf("EventType_%s", strings.ToUpper(oneof.FieldName)))

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
	tetragonProcess := common.TetragonApiIdent(g, "Process")
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

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
	tetragonProcess := common.TetragonApiIdent(g, "Process")

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

			goIdent := common.TetragonApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", msg.GoIdent.GoName))

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
	tetragonProcess := common.TetragonApiIdent(g, "Process")
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

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
	tetragonProcess := common.TetragonApiIdent(g, "Process")

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

			goIdent := common.TetragonApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", msg.GoIdent.GoName))

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
