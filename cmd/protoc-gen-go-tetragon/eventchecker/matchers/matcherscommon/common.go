// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package matcherscommon

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

// A function that produces the inner part of a match case. Available variables
// for the match case are `m` for the matcher and `value` for the value being matched.
type GenerateMatchCase func(g *protogen.GeneratedFile, f *protogen.File) (string, error)

type ConstructorOverride struct {
	Args string
	Body string
}

type MatcherGen struct {
	// The name of the matcher to be generated
	Name string
	// The type name of the type being checked
	Type string
	// The type name of the value held in the matcher (this often matches Type, but not
	// necessarily)
	ValueField string
	// A set of potential alternatives for ValueField if it is an interface.
	// The first in this set will be used for the default case in Unmarshal.
	ValueFieldAlternatives []string
	// Maps an operator name to a function that produces a match case
	OperatorFuncs map[string]GenerateMatchCase
	// Maps an operator name to an args + body pair for generating a custom constructor
	ConstructorOverrides map[string]ConstructorOverride
	// Default operator to unmarshal when user provides a plain type
	DefaultOperator string
	// Set to true if we should add the name of the matcher as a suffix to constructors.
	// Only useful when multiple matchers will share the same file + operation set.
	AddConstructorSuffix bool
	// Set to false if we should generate the Match implementation. Should be set to true when
	// a custom implementation is desired.
	SkipMatch bool
	// Set to false if we should generate the Marshal implementation for the matcher.
	// Should be set to true in the case where you want to write a custom implementation.
	SkipMarshal bool
	// Set to false if we should generate the Operator type. Should be set to true when
	// many matchers will share a file with the same operator type.
	SkipOperatorGen bool
	// Set to false if we should generate the Struct body for the matcher. Should be set
	// to true in the case where you want to write this manually.
	SkipStructGen bool
	// Set to false if we should generate the Unmarshal implementation for the matcher.
	// Should be set to true in the case where you want to write a custom implementation.
	SkipUnmarshal bool
	// Set to false if we should generate Constructors for the matcher.
	// Should be set to true in the case where you want to write a custom implementation.
	SkipConstructors bool
}

func (m *MatcherGen) Operators() []string {
	var ops []string
	for op := range m.OperatorFuncs {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return ops
}

func (m *MatcherGen) Generate(g *protogen.GeneratedFile, f *protogen.File) error {
	if !m.SkipStructGen {
		if err := m.GenerateStruct(g, f); err != nil {
			return fmt.Errorf("Failed to generated matcher struct: %w", err)
		}
	}

	if !m.SkipOperatorGen {
		if err := m.GenerateOperator(g, f); err != nil {
			return fmt.Errorf("Failed to generated operator: %w", err)
		}
	}

	if !m.SkipMatch {
		if err := m.GenerateMatch(g, f); err != nil {
			return fmt.Errorf("Failed to generated match: %w", err)
		}
	}

	if !m.SkipMarshal {
		if err := m.GenerateMarshal(g, f); err != nil {
			return fmt.Errorf("Failed to generated marshal: %w", err)
		}
	}

	if !m.SkipUnmarshal {
		if err := m.GenerateUnmarshal(g, f); err != nil {
			return fmt.Errorf("Failed to generated unmarshal: %w", err)
		}
	}

	if !m.SkipConstructors {
		if err := m.GenerateConstructors(g, f); err != nil {
			return fmt.Errorf("Failed to generated constructors: %w", err)
		}
	}

	return nil
}

func (m *MatcherGen) GenerateStruct(g *protogen.GeneratedFile, f *protogen.File) error {
	g.P(`// ` + m.Name + ` matches a ` + m.Type + ` based on an operator and a value
    type ` + m.Name + ` struct {
        Operator Operator ` + common.StructTag(`json:"operator"`) + `
        Value ` + m.ValueField + ` ` + common.StructTag(`json:"value"`) + `
    }`)

	return nil
}

func (m *MatcherGen) GenerateOperator(g *protogen.GeneratedFile, f *protogen.File) error {
	ops := m.Operators()

	g.P(`// Operator is en enum over types of ` + m.Name + `
    type Operator struct {
        slug string
    }`)

	g.P(`// String implements fmt.Stringer
    func (o Operator) String() string {
        return o.slug
    }`)

	g.P(`// operatorFromString converts a string into Operator
    func operatorFromString(str string) (Operator, error) {
        switch str {`)
	for _, op := range ops {
		g.P(`case op` + op + `.slug:
        return op` + op + `, nil
        `)
	}
	g.P(`
        default:
            return opUnknown, ` + common.FmtErrorf(g, "Invalid value for "+m.Name+" operator: %s", "str") + `
        }
    }`)

	jsonMarshal := common.GoIdent(g, "encoding/json", "Marshal")
	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")
	toLower := common.GoIdent(g, "strings", "ToLower")

	g.P(`// UnmarshalJSON implements json.Unmarshaler interface
    func (o *Operator) UnmarshalJSON(b []byte) error {
        var str string
        err := ` + yamlUnmarshal + `(b, &str)
        if err != nil {
            return err
        }

        str = ` + toLower + `(str)
        operator, err := operatorFromString(str)
        if err != nil {
            return err
        }

        *o = operator
        return nil
    }`)

	g.P(`// MarshalJSON implements json.Marshaler interface
    func (o Operator) MarshalJSON() ([]byte, error) {
        return ` + jsonMarshal + `(o.slug)
    }`)

	g.P(`var (
        opUnknown = Operator{"unknown"}`)
	for _, op := range ops {
		g.P(`op` + op + ` = Operator{"` + strings.ToLower(op) + `"}`)
	}
	g.P(`)`)

	return nil
}

func (m *MatcherGen) GenerateMatch(g *protogen.GeneratedFile, f *protogen.File) error {
	ops := m.Operators()

	g.P(`// Match attempts to match a ` + m.Type + ` based on the ` + m.Name + `
    func (m *` + m.Name + `) Match (value ` + m.Type + `) error {
        switch m.Operator {`)
	for _, op := range ops {
		generateBody := m.OperatorFuncs[op]
		body, err := generateBody(g, f)
		if err != nil {
			return err
		}
		g.P(`case op` + op + `:
        { ` + body + ` }`)
	}
	g.P(`default:
            return ` + common.FmtErrorf(g, "Unhandled "+m.Name+" operator %s", "m.Operator") + `
        }
    }`)

	return nil
}

func (m *MatcherGen) GenerateMarshal(g *protogen.GeneratedFile, f *protogen.File) error {
	// If we don't need a Marshal implementation then don't generate one
	if len(m.ValueFieldAlternatives) == 0 {
		return nil
	}

	jsonMarshal := common.GoIdent(g, "encoding/json", "Marshal")

	doFieldAlternatives := func() string {
		ret := "type Alias " + m.Name + "\n"
		ret += "switch valueType := m.Value.(type) {\n"

		for _, t := range m.ValueFieldAlternatives {
			ret += `case ` + t + `:
                return ` + jsonMarshal + `(&struct {
                    Value ` + t + ` ` + common.StructTag(`json:"value"`) + `
                    *Alias
                }{
                    Value: valueType,
                    Alias: (*Alias)(&m),
                })
                `
		}
		ret += `default:
            return nil, ` + common.FmtErrorf(g, "Marshal DurationMatcher: Invalid match value")

		ret += "\n}"

		return ret
	}

	g.P(`// Marshal implements json.Marshaler
    func (m ` + m.Name + `) MarshalJSON() ([]byte, error) {
        ` + doFieldAlternatives() + `
    }`)

	return nil
}

func (m *MatcherGen) GenerateUnmarshal(g *protogen.GeneratedFile, f *protogen.File) error {
	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")

	var maybeWrapValue func(string) string
	var rawVal string
	if len(m.ValueFieldAlternatives) > 0 {
		rawVal = m.ValueFieldAlternatives[0]
		valIsPointer := strings.HasPrefix(rawVal, "*")
		maybeWrapValue = func(val string) string {
			if valIsPointer {
				return fmt.Sprintf("(%s)(&%s)", m.ValueField, val)
			}
			return fmt.Sprintf("(%s)(%s)", m.ValueField, val)
		}
	} else if m.ValueField != m.Type {
		rawVal = m.ValueField
		valIsPointer := strings.HasPrefix(rawVal, "*")
		maybeWrapValue = func(val string) string {
			if valIsPointer {
				return fmt.Sprintf("(%s)(&%s)", m.ValueField, val)
			}
			return fmt.Sprintf("(%s)(%s)", m.ValueField, val)
		}
	} else {
		rawVal = m.Type
		maybeWrapValue = func(val string) string {
			return val
		}
	}
	rawVal = strings.TrimPrefix(rawVal, "*")

	var doFullUnmarshal func() string
	if len(m.ValueFieldAlternatives) > 0 {
		doFullUnmarshal = func() string {
			ret := `type Alias ` + m.Name

			for _, value := range m.ValueFieldAlternatives {
				ret += `
                {
                    temp := struct {
                        Value ` + value + ` ` + common.StructTag(`json:"value"`) + `
                        *Alias
                    }{Alias: (*Alias)(m)}
                    if err := ` + yamlUnmarshal + `(b, &temp); err == nil {
                        m.Value = temp.Value
                        return nil
                    }
                }`
			}

			ret += "\nreturn " + common.FmtErrorf(g, "Unmarshal "+m.Name+": Failed to unmarshal")

			return ret
		}
	} else {
		doFullUnmarshal = func() string {
			return `type Alias ` + m.Name + `
            var alias Alias
            err = ` + yamlUnmarshal + `(b, &alias)
            if err != nil {
                return ` + common.FmtErrorf(g, "Unmarshal "+m.Name+": %w", "err") + `
            }
            *m = ` + m.Name + `(alias)
			return nil `
		}
	}

	g.P(`// Unmarshal implements json.Unmarshaler
    func (m *` + m.Name + `) UnmarshalJSON(b []byte) error {
        // User just provides a plain ` + m.ValueField + `, so default to ` + m.DefaultOperator + `
        var rawVal ` + rawVal + `
        err := ` + yamlUnmarshal + `(b, &rawVal)
        if err == nil {
            m.Operator = op` + m.DefaultOperator + `
            m.Value = ` + maybeWrapValue("rawVal") + `
            return nil
        }

        ` + doFullUnmarshal() + `
    }`)

	return nil
}

func (m *MatcherGen) GenerateConstructors(g *protogen.GeneratedFile, f *protogen.File) error {
	ops := m.Operators()

	for _, op := range ops {
		funcName := op
		if m.AddConstructorSuffix {
			funcName += m.Name
		}

		var args string
		var body string
		if override, ok := m.ConstructorOverrides[op]; ok {
			args = override.Args
			body = override.Body
		} else {
			args = "value " + m.Type
			body = `return &` + m.Name + `{
                Operator: op` + op + `,
                Value: value,
            }`
		}

		g.P(`// ` + funcName + ` constructs a new ` + m.Name + ` that matches using the ` + op + ` operator
        func ` + funcName + `(` + args + `) *` + m.Name + ` {
            ` + body + `
        }
        `)
	}

	return nil
}
