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

	// Codegen the spec
	g.P(`// EventCheckerSpec is a YAML spec to define an event checker
    type EventCheckerSpec struct {`)

	for _, event := range events {
		jsonName := strcase.ToLowerCamel(strings.TrimPrefix(event.GoIdent.GoName, "Process"))
		checkerIdent := common.GeneratedIdent(g, "eventchecker", event.checkerName())
		g.P(event.GoIdent.GoName + `*` + checkerIdent +
			common.StructTag(fmt.Sprintf("json:\"%s,omitempty\"", jsonName)))
	}

	g.P(`}`)

	eventCheckerInterface := common.GeneratedIdent(g, "eventchecker", "EventChecker")

	// Codegen the IntoEventChecker method
	g.P(`// IntoEventChecker coerces an event checker from this spec
    func (spec *EventCheckerSpec) IntoEventChecker() (` + eventCheckerInterface + `, error) {
        var eventChecker ` + eventCheckerInterface)

	for _, event := range events {
		g.P(`if spec.` + event.GoIdent.GoName + ` != nil {
            if eventChecker != nil {
                return nil, ` + common.FmtErrorf(g, "EventCheckerSpec cannot define more than one checker, got %T but already had %T", "spec."+event.GoIdent.GoName, "eventChecker") + `
            }
            eventChecker = spec.` + event.GoIdent.GoName + `
        }`)
	}

	g.P(`if eventChecker == nil {
            return nil, ` + common.FmtErrorf(g, "EventCheckerSpec didn't define any event checker") + `
        }
        return eventChecker, nil
    }`)

	// Codegen SpecFromEventChecker
	g.P(`// SpecFromEventChecker creates a new EventCheckerSpec from an EventChecker
    func SpecFromEventChecker(checker ` + eventCheckerInterface + `) (*EventCheckerSpec, error) {
        var spec EventCheckerSpec
        switch c := checker.(type) {`)

	for _, event := range events {
		checkerIdent := common.GeneratedIdent(g, "eventchecker", event.checkerName())
		g.P(`case *` + checkerIdent + `:
            spec.` + event.GoIdent.GoName + ` = c`)
	}

	g.P(`
        default:
            return nil, ` + common.FmtErrorf(g, "Unhandled checker type %T", "c") + `
        }
        return &spec, nil
    }`)

	// Codegen UnarshalJSON implementation
	unmarshalStrict := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")
	g.P(`// UnmarshalJSON implements json.Unmarshaler interface
    func (spec *EventCheckerSpec) UnmarshalJSON(b []byte) (error) {
        type alias EventCheckerSpec
        var spec2 alias
        if err := ` + unmarshalStrict + `(b, &spec2); err != nil {
            return err
        }
        *spec = EventCheckerSpec(spec2)

        var eventChecker ` + eventCheckerInterface)

	for _, event := range events {
		g.P(`if spec.` + event.GoIdent.GoName + ` != nil {
            if eventChecker != nil {
                return ` + common.FmtErrorf(g, "EventCheckerSpec cannot define more than one checker, got %T but already had %T", "spec."+event.GoIdent.GoName, "eventChecker") + `
            }
            eventChecker = spec.` + event.GoIdent.GoName + `
        }`)
	}

	g.P(`if eventChecker == nil {
        return ` + common.FmtErrorf(g, "EventCheckerSpec didn't define any event checker") + `
    }
    return nil
    }`)

	return nil
}

// Generate generates boilerplate code for the multi eventchecker spec
func generateMultiEventCheckerSpec(g *protogen.GeneratedFile, f *protogen.File) error {
	g.P(`// MultiEventCheckerSpec is a YAML spec to define a MultiEventChecker
    type MultiEventCheckerSpec struct {
        Ordered bool               ` + common.StructTag("json:\"ordered\"") + `
        Checks  []EventCheckerSpec ` + common.StructTag("json:\"checks\"") + `
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
            checker, err := check.IntoEventChecker()
            if err != nil {
                return nil, err
            }
            checkers = append(checkers, checker)
        }

        if spec.Ordered {
            return ` + newOrderedEventChecker + `(checkers...), nil
        }

        return ` + newUnorderedEventChecker + `(checkers...), nil
    }`)

	// Codegen the SpecFromMultiEventChecker method
	g.P(`// SpecFromMultiEventChecker coerces an event checker from this spec
    func SpecFromMultiEventChecker(checker ` + multiEventCheckerInterface + `) (*MultiEventCheckerSpec, error) {
        var spec MultiEventCheckerSpec
        var specs []EventCheckerSpec

        for _, check := range checker.GetChecks() {
            spec, err := SpecFromEventChecker(check)
            if err != nil {
                return nil, err
            }
            specs = append(specs, *spec)
        }

        spec.Checks = specs

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
