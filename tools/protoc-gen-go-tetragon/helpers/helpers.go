// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

func generateResponseTypeString(g *protogen.GeneratedFile, files []*protogen.File) error {
	oneofs, err := common.GetEventsResponseOneofs(files)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, oneof := range oneofs {
			msgGoIdent := common.TetragonApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", oneof.TypeName))
			typeGoIdent := common.TetragonApiIdent(g, fmt.Sprintf("EventType_%s", strings.ToUpper(oneof.FieldName)))

			ret += `case *` + msgGoIdent + `:
                return ` + typeGoIdent + `.String(), nil
            `
		}
		return ret
	}

	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseTypeString returns an event's type as a string
    func ResponseTypeString(response *` + tetragonGER + `) (string, error) {
        if response == nil {
            return "", ` + common.FmtErrorf(g, "Response is nil") + `
        }

        event := response.Event
        if event == nil {
            return "", ` + common.FmtErrorf(g, "Event is nil") + `
        }

        switch event.(type) {
            ` + doCases() + `
        }
        return "", ` + common.FmtErrorf(g, "Unhandled response type %T", "event") + `
        }`)

	return nil
}

func generateResponseGetProcess(g *protogen.GeneratedFile) error {
	tetragonProcess := common.ProcessIdent(g)
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetProcess returns a GetEventsResponse's process if it exists
    func ResponseGetProcess(response *` + tetragonGER + `) *` + tetragonProcess + ` {
        if response == nil {
            return nil
        }

        event := response.Event
        if event == nil {
            return nil
        }

        return ResponseInnerGetProcess(event)
	 }`)

	return nil
}

func generateResponseInnerGetProcess(g *protogen.GeneratedFile, files []*protogen.File) error {
	events, err := common.GetEvents(files)
	if err != nil {
		return err
	}

	tetragonProcess := common.ProcessIdent(g)

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

	ifaceIdent := common.TetragonApiIdent(g, "IsGetEventsResponse_Event")

	g.P(`// ResponseInnerGetProcess returns a GetEventsResponse inner event's process if it exists
    func ResponseInnerGetProcess(event ` + ifaceIdent + `) *` + tetragonProcess + ` {
        switch ev := event.(type) {
            ` + doCases() + `
        }
        return nil
	 }`)

	return nil
}

func generateResponseGetProcessKprobe(g *protogen.GeneratedFile) error {
	processKprobe := common.ProcessKprobeIdent(g)
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetProcessKprobe returns a GetEventsResponse's process if it exists
    func ResponseGetProcessKprobe(response *` + tetragonGER + `) *` + processKprobe + ` {
        if response == nil {
            return nil
        }

		return response.GetProcessKprobe()
	 }`)

	return nil
}

func generateResponseGetParent(g *protogen.GeneratedFile) error {
	tetragonProcess := common.ProcessIdent(g)
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetParent returns a GetEventsResponse's parent process if it exists
    func ResponseGetParent(response *` + tetragonGER + `) *` + tetragonProcess + ` {
        if response == nil {
            return nil
        }

        event := response.Event
        if event == nil {
            return nil
        }

        return ResponseInnerGetParent(event)
	 }`)

	return nil
}

func generateResponseInnerGetParent(g *protogen.GeneratedFile, files []*protogen.File) error {
	events, err := common.GetEvents(files)
	if err != nil {
		return err
	}

	tetragonProcess := common.ProcessIdent(g)

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

	ifaceIdent := common.TetragonApiIdent(g, "IsGetEventsResponse_Event")

	g.P(`// ResponseInnerGetParent returns a GetEventsResponse inner event's parent process if it exists
    func ResponseInnerGetParent(event ` + ifaceIdent + `) *` + tetragonProcess + ` {
        switch ev := event.(type) {
            ` + doCases() + `
        }
        return nil
	 }`)

	return nil
}

func generateResponseGetAncestors(g *protogen.GeneratedFile) error {
	tetragonProcess := common.ProcessIdent(g)
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")

	g.P(`// ResponseGetAncestors returns a GetEventsResponse's ancestors processes if they exists
    func ResponseGetAncestors(response *` + tetragonGER + `) []*` + tetragonProcess + ` {
        if response == nil {
            return nil
        }

        event := response.Event
        if event == nil {
            return nil
        }

        return ResponseInnerGetAncestors(event)
	 }`)

	return nil
}

func generateResponseInnerGetAncestors(g *protogen.GeneratedFile, files []*protogen.File) error {
	events, err := common.GetEvents(files)
	if err != nil {
		return err
	}

	tetragonProcess := common.ProcessIdent(g)

	doCases := func() string {
		var ret string
		for _, msg := range events {
			if !common.IsAncestorsEvent(msg) {
				continue
			}

			goIdent := common.TetragonApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", msg.GoIdent.GoName))

			ret += `case *` + goIdent + `:
                return ev.` + msg.GoIdent.GoName + `.Ancestors
            `
		}
		return ret
	}

	ifaceIdent := common.TetragonApiIdent(g, "IsGetEventsResponse_Event")

	g.P(`// ResponseInnerGetAncestors returns a GetEventsResponse inner event's ancestors processes if they exists
    func ResponseInnerGetAncestors(event ` + ifaceIdent + `) []*` + tetragonProcess + ` {
        switch ev := event.(type) {
            ` + doCases() + `
        }
        return nil
	 }`)

	return nil
}

func generateResponseTypeMap(g *protogen.GeneratedFile, files []*protogen.File) error {
	oneofs, err := common.GetEventsResponseOneofs(files)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, oneof := range oneofs {
			msgGoIdent := common.TetragonApiIdent(g, oneof.TypeName)
			ret += fmt.Sprintf("\"%s\": &%s{},\n", oneof.FieldName, msgGoIdent)
		}
		return ret
	}

	protoMessage := common.GoIdent(g, "google.golang.org/protobuf/proto", "Message")
	g.P(`// ResponseTypeMap returns a map from event field names (e.g. "process_exec") to corresponding
    // protobuf messages (e.g. &tetragon.ProcessExec{}).
    func ResponseTypeMap() map[string]` + protoMessage + `{
		return map[string]proto.Message {
            ` + doCases() + `
        }
    }`)

	return nil
}

func generateProcessEventMap(g *protogen.GeneratedFile, files []*protogen.File) error {
	oneofs, err := common.GetEventsResponseOneofs(files)
	if err != nil {
		return err
	}

	doCases := func() string {
		var ret string
		for _, oneof := range oneofs {
			msgGoIdent := strings.Split(common.TetragonApiIdent(g, oneof.TypeName), ".")
			ret += fmt.Sprintf("\"%s\": response.Get%s(),\n", oneof.FieldName, msgGoIdent[len(msgGoIdent)-1])
		}
		return ret
	}

	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")
	g.P(`// ProcessEventMap returns a map from event field names (e.g. "process_exec") to corresponding
    // protobuf messages in a given tetragon.GetEventsResponse (e.g. response.GetProcessExec()).
    func ProcessEventMap(response *` + tetragonGER + `) map[string]any {
		return map[string]any {
            ` + doCases() + `
        }
    }`)

	return nil
}

// Generate generates boilerplate helpers
func Generate(gen *protogen.Plugin, files []*protogen.File) error {
	// Pick arbitrary file to use for prefix of generated files, files[0] here.
	g := common.NewCodegenFile(gen, files[0], "helpers")

	if err := generateResponseTypeString(g, files); err != nil {
		return err
	}

	if err := generateResponseGetProcess(g); err != nil {
		return err
	}

	if err := generateResponseInnerGetProcess(g, files); err != nil {
		return err
	}

	if err := generateResponseGetProcessKprobe(g); err != nil {
		return err
	}

	if err := generateResponseGetParent(g); err != nil {
		return err
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := generateResponseInnerGetParent(g, files); err != nil {
		return err
	}

	if err := generateResponseGetAncestors(g); err != nil {
		return err
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := generateResponseInnerGetAncestors(g, files); err != nil {
		return err
	}

	if err := generateResponseTypeMap(g, files); err != nil {
		return err
	}

	if err := generateProcessEventMap(g, files); err != nil {
		return err
	}

	return nil
}
