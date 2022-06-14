// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

type CheckedMessage protogen.Message

func (msg *CheckedMessage) Generate(g *protogen.GeneratedFile, isEvent bool) error {
	if err := msg.generateChecker(g, isEvent); err != nil {
		return err
	}

	for _, rawField := range msg.Fields {
		field := (*Field)(rawField)
		if !field.isList() {
			continue
		}
		if err := field.generateListMatcher(g); err != nil {
			return fmt.Errorf("Failed to generate list checker: %w", err)
		}
	}

	return nil
}

func (msg *CheckedMessage) generateChecker(g *protogen.GeneratedFile, isEvent bool) error {
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")
	targetIdent := common.TetragonApiIdent(g, msg.GoIdent.GoName)

	var msgType string
	if isEvent {
		msgType = "event"
	} else {
		msgType = "field"
	}

	fieldsStr, err := msg.fieldsBody(g)
	if err != nil {
		return err
	}

	g.P(`// ` + msg.checkerName(g) + ` implements a checker struct to check a ` + msg.GoIdent.GoName + ` ` + msgType + `
        type ` + msg.checkerName(g) + ` struct {
            ` + fieldsStr + `
        }`)

	// Generate the EventChecker implementation
	if isEvent {
		g.P(`// CheckEvent checks a single event and implements the EventChecker interface
        func (checker *` + msg.checkerName(g) + `) CheckEvent(event Event) error {
            if ev, ok := event.(*` + targetIdent + `); ok {
                return checker.Check(ev)
            }
            return ` + common.FmtErrorf(g, "%T is not a "+msg.GoIdent.GoName+" event", "event") + `
        }`)

		g.P(`// CheckResponse checks a single gRPC response and implements the EventChecker interface
        func (checker *` + msg.checkerName(g) + `) CheckResponse(response *` + tetragonGER + `) error {
            event, err := EventFromResponse(response)
            if err != nil {
                return err
            }
            return checker.CheckEvent(event)
        }`)

	}

	g.P(`// New` + msg.checkerName(g) + ` creates a new ` + msg.checkerName(g) + `
    func New` + msg.checkerName(g) + `() *` + msg.checkerName(g) + ` {
        return &` + msg.checkerName(g) + `{}
    }
    `)

	// Do preamble
	g.P(`// Check checks a ` + msg.GoIdent.GoName + ` ` + msgType + `
        func (checker *` + msg.checkerName(g) + `) Check(event *` + targetIdent + `) error {
            if event == nil {
                return ` + common.FmtErrorf(g, msg.checkerName(g)+": "+msg.GoIdent.GoName+" "+msgType+" "+"is nil") + `
            }
        `)
	// Do fields
	for _, rawField := range msg.Fields {
		field := (*Field)(rawField)
		field.generateFieldCheck(g, msg)
	}
	// Do final return
	g.P(`return nil
    }`)

	// Generate With funcs
	for _, rawField := range msg.Fields {
		field := (*Field)(rawField)
		field.generateWith(g, msg)
	}

	// Generate From funcs
	g.P(`//From` + msg.GoIdent.GoName + ` populates the ` + msg.checkerName(g) + ` using data from a ` + msg.GoIdent.GoName + ` ` + msgType + `
    func (checker *` + msg.checkerName(g) + `) From` + msg.GoIdent.GoName + `(event *` + targetIdent + `) *` + msg.checkerName(g) + ` {
        if event == nil {
            return checker
        }`)
	// Do fields
	for _, rawField := range msg.Fields {
		field := (*Field)(rawField)
		field.generateFrom(g, msg)
	}
	g.P(`return checker
    }`)

	return nil
}

func (msg *CheckedMessage) checkerName(g *protogen.GeneratedFile) string {
	ret := fmt.Sprintf("%sChecker", msg.GoIdent.GoName)
	typeImportPath := string(msg.GoIdent.GoImportPath)
	if !strings.HasPrefix(typeImportPath, common.TetragonPackageName) {
		importPath := filepath.Join(typeImportPath, "codegen", "eventchecker")
		ret = g.QualifiedGoIdent(protogen.GoIdent{
			GoName:       ret,
			GoImportPath: protogen.GoImportPath(importPath),
		})
	}
	return ret
}

func (msg *CheckedMessage) fieldsBody(g *protogen.GeneratedFile) (string, error) {
	var fieldsStr string
	for _, field := range msg.Fields {
		f := (*Field)(field)
		typeName, err := f.typeName(g)
		if err != nil {
			return "", err
		}
		if !(f.isList() || f.isMap()) {
			fieldsStr += fmt.Sprintf("%s *%s `%s`\n", f.name(), typeName, f.jsonTag())
		} else if f.isList() {
			fieldsStr += fmt.Sprintf("%s *%s `%s`\n", f.name(), f.listCheckerName(g), f.jsonTag())
		} else {
			fieldsStr += fmt.Sprintf("%s %s `%s`\n", f.name(), typeName, f.jsonTag())
		}
	}
	return fieldsStr, nil
}
