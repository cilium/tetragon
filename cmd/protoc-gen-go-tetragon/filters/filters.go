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

package filters

import (
	"fmt"
	"log"
	"strings"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"github.com/iancoleman/strcase"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func generateOpCodeForEventType(g *protogen.GeneratedFile, f *protogen.File) error {
	reflectType := common.GoIdent(g, "reflect", "Type")
	reflectTypeOf := common.GoIdent(g, "reflect", "TypeOf")
	fgsEventType := common.FgsApiIdent(g, "EventType")

	enumIndex := -1
	for i, enum := range f.Enums {
		if enum.GoIdent.GoName == "EventType" {
			enumIndex = i
		}
	}
	if enumIndex == -1 {
		return fmt.Errorf("Enum EventType not found")
	}
	enum := f.Enums[enumIndex]

	g.P(`func OpCodeForEventType(eventType ` + fgsEventType + `) (` + reflectType + `, error) {
        var opCode ` + reflectType + `
        switch eventType {`)

	for _, value := range enum.Values {
		valueIdent := g.QualifiedGoIdent(value.GoIdent)
		// skip over the UNDEF variant
		if valueIdent == "fgs.EventType_UNDEF" {
			continue
		}

		response, err := eventTypeToResponse(g, f, value)
		if err != nil {
			return err
		}
		if response == "" {
			continue
		}
		g.P(`case ` + valueIdent + `:
                opCode = ` + reflectTypeOf + `(&` + response + `{})`)
	}

	g.P(` default:
            return nil, ` + common.FmtErrorf(g, "Unknown EventType %s", "eventType") + `
        }
        return opCode, nil
    }`)

	return nil
}

func eventTypeToResponse(g *protogen.GeneratedFile, f *protogen.File, eventType *protogen.EnumValue) (string, error) {
	snakeSuffix := strings.ToLower(strings.TrimPrefix(eventType.GoIdent.GoName, "EventType_"))
	suffix := strcase.ToCamel(snakeSuffix)
	name := fmt.Sprintf("GetEventsResponse_%s", suffix)

	ger := f.Desc.Messages().ByName("GetEventsResponse")
	if ger == nil {
		return "", fmt.Errorf("Unable to find GetEventsResponse message")
	}

	oneof := ger.Oneofs().ByName("event")
	if oneof == nil {
		return "", fmt.Errorf("Unable to find GetEventsResponse.event oneof")
	}

	if oneof.Fields().ByName(protoreflect.Name(snakeSuffix)) == nil {
		log.Printf("%s does not exist", name)
		return "", nil
	}

	return common.FgsApiIdent(g, name), nil
}

// Generate generates boilerplate code for the filters
func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewGeneratedFile(gen, f, "filters")

	if err := generateOpCodeForEventType(g, f); err != nil {
		return err
	}

	return nil
}
