// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"github.com/iancoleman/strcase"
	"google.golang.org/protobuf/compiler/protogen"
)

// Generate generates boilerplate code for the eventchecker spec
func generateEventCheckerSpec(g *protogen.GeneratedFile, f *protogen.File) error {
	events, err := getEvents(f)
	if err != nil {
		return err
	}

	eventCheckerInterface := common.GeneratedIdent(g, "eventchecker", "EventChecker")
	unmarshalStrict := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")
	jsonMarshal := common.GoIdent(g, "encoding/json", "Marshal")

	g.P(`type eventCheckerHelper struct {`)
	for _, event := range events {
		jsonName := strcase.ToLowerCamel(strings.TrimPrefix(event.GoIdent.GoName, "Process"))
		checkerIdent := common.GeneratedIdent(g, "eventchecker", event.checkerName(g))
		g.P(event.GoIdent.GoName + `*` + checkerIdent +
			common.StructTag(fmt.Sprintf("json:\"%s,omitempty\"", jsonName)))
	}
	g.P(`}`)

	g.P(`// EventChecker is a wrapper around the EventChecker interface to help unmarshaling
    type EventChecker struct {
        ` + eventCheckerInterface + `
    }`)

	g.P(`// UnmarshalJSON implements the json.Unmarshaler interface
    func (checker *EventChecker) UnmarshalJSON(b []byte) error {
        var eventChecker ` + eventCheckerInterface + `
        var helper eventCheckerHelper
        if err := ` + unmarshalStrict + `(b, &helper); err != nil {
            return err
        }`)
	for _, event := range events {
		g.P(`if helper.` + event.GoIdent.GoName + ` != nil {
            if eventChecker != nil {
                return ` + common.FmtErrorf(g, "EventChecker: cannot define more than one checker, got %T but already had %T", "helper."+event.GoIdent.GoName, "eventChecker") + `
            }
            eventChecker = helper.` + event.GoIdent.GoName + `
        }`)
	}
	g.P(`checker.EventChecker = eventChecker
        return nil
    }`)

	g.P(`// MarshalJSON implements the json.Marshaler interface
    func (checker EventChecker) MarshalJSON() ([]byte, error) {
        var helper eventCheckerHelper
        switch c := checker.EventChecker.(type) {`)
	for _, event := range events {
		checkerIdent := common.GeneratedIdent(g, "eventchecker", event.checkerName(g))
		g.P(`case *` + checkerIdent + `:
            helper.` + event.GoIdent.GoName + ` = c`)
	}
	g.P(`default:
            return nil, ` + common.FmtErrorf(g, "EventChecker: unknown checker type %T", "c") + `
        }
        return ` + jsonMarshal + `(helper)
    }`)

	return nil
}

// Generate generates boilerplate code for the multi eventchecker spec
func generateMultiEventCheckerSpec(g *protogen.GeneratedFile, f *protogen.File) error {
	g.P(`// MultiEventCheckerSpec is a YAML spec to define a MultiEventChecker
    type MultiEventCheckerSpec struct {
        Ordered bool           ` + common.StructTag("json:\"ordered\"") + `
        Checks  []EventChecker ` + common.StructTag("json:\"checks\"") + `
	}`)

	eventCheckerInterface := common.GeneratedIdent(g, "eventchecker", "EventChecker")
	multiEventCheckerInterface := common.GeneratedIdent(g, "eventchecker", "MultiEventChecker")
	newOrderedEventChecker := common.GeneratedIdent(g, "eventchecker", "NewOrderedEventChecker")
	newUnorderedEventChecker := common.GeneratedIdent(g, "eventchecker", "NewUnorderedEventChecker")
	orderedEventChecker := common.GeneratedIdent(g, "eventchecker", "OrderedEventChecker")
	unorderedEventChecker := common.GeneratedIdent(g, "eventchecker", "UnorderedEventChecker")

	// Codegen the IntoMultiEventChecker method
	g.P(`// IntoMultiEventChecker coerces an event checker from this spec
    func (spec *MultiEventCheckerSpec) IntoMultiEventChecker() (` + multiEventCheckerInterface + `, error) {
        var checkers []` + eventCheckerInterface + `

        for _, check := range spec.Checks {
            checkers = append(checkers, check.EventChecker)
        }

        if spec.Ordered {
            return ` + newOrderedEventChecker + `(checkers...), nil
        }

        return ` + newUnorderedEventChecker + `(checkers...), nil
    }`)

	// Codegen the SpecFromMultiEventChecker method
	g.P(`// SpecFromMultiEventChecker coerces a spec from a MultiEventChecker
    func SpecFromMultiEventChecker(checker_ ` + multiEventCheckerInterface + `) (*MultiEventCheckerSpec, error) {
        var spec MultiEventCheckerSpec

        checker, ok := checker_.(interface{ GetChecks() []` + eventCheckerInterface + `})
        if !ok {
                return nil, ` + common.FmtErrorf(g, "Unhandled checker type %T", "checker_") + `
        }

        for _, check := range checker.GetChecks() {
            spec.Checks = append(spec.Checks, EventChecker{check})
        }

        switch checker.(type) {
        case *` + orderedEventChecker + `:
            spec.Ordered = true
        case *` + unorderedEventChecker + `:
            spec.Ordered = false
        default:
            return nil, ` + common.FmtErrorf(g, "Unhandled checker type %T", "checker") + `
        }

        return &spec, nil
    }`)

	return nil
}

func generateEventCheckerConf(g *protogen.GeneratedFile, f *protogen.File) error {
	g.P(`// Metadata contains metadata for the eventchecker definition
    type Metadata struct {
        Name string ` + common.StructTag(`json:"name"`) + `
        Description string ` + common.StructTag(`json:"description"`) + `
    }`)

	g.P(`// Metadata contains metadata for the eventchecker definition
    type EventCheckerConf struct {
        APIVersion string ` + common.StructTag(`json:"apiVersion"`) + `
        Kind string ` + common.StructTag(`json:"kind"`) + `
        Metadata Metadata ` + common.StructTag(`json:"metadata"`) + `
        Spec MultiEventCheckerSpec ` + common.StructTag(`json:"spec"`) + `
    }`)

	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")
	yamlMarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "Marshal")
	template := common.GoIdent(g, "text/template", "New")
	osWriteFile := common.GoIdent(g, "os", "WriteFile")
	osReadFile := common.GoIdent(g, "os", "ReadFile")
	bytesBuffer := common.GoIdent(g, "bytes", "Buffer")

	g.P(`// ConfFromSpec creates a new EventCheckerConf from a MultiEventCheckerSpec
    func ConfFromSpec(apiVersion, name, description string,
        spec *MultiEventCheckerSpec) (*EventCheckerConf, error) {
        if spec == nil {
            return nil, ` + common.FmtErrorf(g, "spec is nil") + `
        }

        return &EventCheckerConf{
            APIVersion: apiVersion,
            Kind: "EventChecker",
            Metadata: Metadata{
                Name:        name,
                Description: description,
            },
            Spec: *spec,
        }, nil
    }

    // ConfFromChecker creates a new EventCheckerConf from a MultiEventChecker
    func ConfFromChecker(apiVersion, name, description string,
        checker eventchecker.MultiEventChecker) (*EventCheckerConf, error) {
        spec, err := SpecFromMultiEventChecker(checker)
        if err != nil {
            return nil, err
        }

        return &EventCheckerConf{
            APIVersion: apiVersion,
            Kind: "EventChecker",
            Metadata: Metadata{
                Name:        name,
                Description: description,
            },
            Spec: *spec,
        }, nil
    }

    // ReadYaml reads an event checker from yaml
    func ReadYaml(data string) (*EventCheckerConf, error) {
        var conf EventCheckerConf

        err := ` + yamlUnmarshal + `([]byte(data), &conf)
        if err != nil {
            return nil, err
        }

        return &conf, nil
    }

    // ReadYamlFile reads an event checker from a yaml file
    func ReadYamlFile(file string) (*EventCheckerConf, error) {
        data, err := ` + osReadFile + `(file)
        if err != nil {
            return nil, err
        }

        return ReadYaml(string(data))
    }

    // ReadYamlTemplate reads an event checker template from yaml
    func ReadYamlTemplate(text string, data interface{}) (*EventCheckerConf, error) {
        var conf EventCheckerConf

        templ := ` + template + `("checkerYaml")
        templ, err := templ.Parse(text)
        if err != nil {
            return nil, err
        }

        var buf ` + bytesBuffer + `
        templ.Execute(&buf, data)

        err = ` + yamlUnmarshal + `(buf.Bytes(), &conf)
        if err != nil {
            return nil, err
        }

        return &conf, nil
    }

    // ReadYamlFileTemplate reads an event checker template from yaml
    func ReadYamlFileTemplate(file string, data interface{}) (*EventCheckerConf, error) {
        text, err := ` + osReadFile + `(file)
        if err != nil {
            return nil, err
        }

        return ReadYamlTemplate(string(text), data)
    }

    // WriteYaml writes an event checker to yaml
    func (conf *EventCheckerConf) WriteYaml() (string, error) {
        data, err := ` + yamlMarshal + `(conf)
        if err != nil {
            return "", err
        }

        return string(data), nil
    }

    // WriteYamlFile writes an event checker to a yaml file
    func (conf *EventCheckerConf) WriteYamlFile(file string) error {
        data, err := conf.WriteYaml()
        if err != nil {
            return err
        }

        return ` + osWriteFile + `(file, []byte(data), 0o644)
    }`)

	return nil
}
