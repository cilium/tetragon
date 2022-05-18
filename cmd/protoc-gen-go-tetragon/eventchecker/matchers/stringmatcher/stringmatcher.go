// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package stringmatcher

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/matcherscommon"
	"google.golang.org/protobuf/compiler/protogen"
)

func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewGeneratedFile(gen, f, "eventchecker/matchers/stringmatcher")

	if err := matcher.Generate(g, f); err != nil {
		return err
	}

	regexp := common.GoIdent(g, "regexp", "Regexp")

	// Custom struct body
	g.P(`// ` + matcher.Name + ` matches a ` + matcher.Type + ` based on an operator and a value
    type ` + matcher.Name + ` struct {
        Operator Operator ` + common.StructTag(`json:"operator"`) + `
        Value ` + matcher.ValueField + ` ` + common.StructTag(`json:"value"`) + `
        regex *` + regexp + ` ` + common.StructTag(`json:"-"`) + `
    }`)

	// Custom unmarshal
	if err := generateUnmarshal(&matcher, g, f); err != nil {
		return fmt.Errorf("Failed to generated marshal: %w", err)
	}

	return nil
}

func generateUnmarshal(m *matcherscommon.MatcherGen, g *protogen.GeneratedFile, f *protogen.File) error {
	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")

	regexpCompile := common.GoIdent(g, "regexp", "Compile")

	doFullUnmarshal := func() string {
		return `type Alias ` + m.Name + `
        var alias Alias
        err = ` + yamlUnmarshal + `(b, &alias)
        if err != nil {
            return ` + common.FmtErrorf(g, "Unmarshal "+m.Name+": %w", "err") + `
        }
        *m = ` + m.Name + `(alias)

        // Compile the regex ahead of time to we can return an unmarshal error if it fails
        // and we won't have to do it on every match
        if m.Operator == opRegex {
            re, err := ` + regexpCompile + `(m.Value)
            if err != nil {
                return ` + common.FmtErrorf(g, "Unmarshal StringMatcher: Invalid regex '%s': %v", "m.Value", "err") + `
            }
            m.regex = re
        }`
	}

	g.P(`// Unmarshal implements json.Unmarshaler
    func (m *` + m.Name + `) UnmarshalJSON(b []byte) error {
        // User just provides a plain ` + m.Type + `, so default to ` + m.DefaultOperator + `
        var rawVal string
        err := ` + yamlUnmarshal + `(b, &rawVal)
        if err == nil {
            m.Operator = op` + m.DefaultOperator + `
            m.Value = rawVal
            return nil
        }

        ` + doFullUnmarshal() + `

        return nil
    }`)

	return nil
}

var matcher = matcherscommon.MatcherGen{
	Name:                   "StringMatcher",
	Type:                   "string",
	ValueField:             "string",
	ValueFieldAlternatives: []string{},
	DefaultOperator:        "Full",
	AddConstructorSuffix:   false,
	SkipMatch:              false,
	SkipMarshal:            false,
	SkipOperatorGen:        false,
	SkipStructGen:          true,
	SkipUnmarshal:          true,
	SkipConstructors:       false,
	OperatorFuncs: map[string]matcherscommon.GenerateMatchCase{
		"Full": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if value == m.Value {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%s' does not match full '%s'", "value", "m.Value")

			return res, nil
		},
		"Prefix": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			stringsPrefix := common.GoIdent(g, "strings", "HasPrefix")

			res := `if ` + stringsPrefix + `(value, m.Value) {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%s' does not have prefix '%s'", "value", "m.Value")

			return res, nil
		},
		"Suffix": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			stringsSuffix := common.GoIdent(g, "strings", "HasSuffix")

			res := `if ` + stringsSuffix + `(value, m.Value) {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%s' does not have suffix '%s'", "value", "m.Value")

			return res, nil
		},
		"Contains": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			stringsContains := common.GoIdent(g, "strings", "Contains")

			res := `if ` + stringsContains + `(value, m.Value) {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%s' does not contain '%s'", "value", "m.Value")

			return res, nil
		},
		"Regex": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			regexpCompile := common.GoIdent(g, "regexp", "Compile")

			res := `// Compile the regex if it hasn't already been compiled
            if m.regex == nil {
                var err error
                m.regex, err = ` + regexpCompile + `(m.Value)
                if err != nil {
                    return ` + common.FmtErrorf(g, "Invalid regex '%s': %v", "m.Value", "err") + `
                }
            }

            // Check whether the regex matches
            if m.regex.Match([]byte(value)) {
                return nil
            }

            return ` + common.FmtErrorf(g, "'%s' does not match regex '%s'", "value", "m.Value") + `
            `
			return res, nil
		},
	},
}
