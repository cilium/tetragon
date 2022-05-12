//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

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
	fgsProcess := common.FgsApiIdent(g, "Process")
	fgsGER := common.FgsApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetProcess gets the process field for a response if it exists
    func ResponseGetProcess(response response) *` + fgsProcess + ` {
        if response == nil {
            return nil
        }
        switch res := response.(type) {
             case *` + fgsGER + `:
                 return EventGetProcess(res.Event)
         }
         return nil
	 }`)

	return nil
}

func generateEventGetProcess(g *protogen.GeneratedFile, f *protogen.File) error {
	fgsProcess := common.FgsApiIdent(g, "Process")

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
    func EventGetProcess(event event) *` + fgsProcess + ` {
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
	fgsProcess := common.FgsApiIdent(g, "Process")
	fgsGER := common.FgsApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetParent gets the parent field for a response if it exists
    func ResponseGetParent(response response) *` + fgsProcess + ` {
        if response == nil {
            return nil
        }
        switch res := response.(type) {
             case *` + fgsGER + `:
                 return EventGetParent(res.Event)
         }
         return nil
	 }`)

	return nil
}

func generateEventGetParent(g *protogen.GeneratedFile, f *protogen.File) error {
	fgsProcess := common.FgsApiIdent(g, "Process")

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
    func EventGetParent(event event) *` + fgsProcess + ` {
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
