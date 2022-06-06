// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package durationmatcher

import (
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/matcherscommon"
	"google.golang.org/protobuf/compiler/protogen"
)

func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewCodegenFile(gen, f, "eventchecker/matchers/durationmatcher")

	// Force an import of durationpb.Duration
	common.GoIdent(g, "google.golang.org/protobuf/types/known/durationpb", "Duration")

	timeDuration := common.GoIdent(g, "time", "Duration")
	timeParseDuration := common.GoIdent(g, "time", "ParseDuration")
	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")
	jsonMarshal := common.GoIdent(g, "encoding/json", "Marshal")

	g.P(`type Duration struct {
        ` + timeDuration + `
    }

    func (d *Duration) UnmarshalJSON(b []byte) error {
        var str string
        err := ` + yamlUnmarshal + `(b, &str)
        if err != nil {
            return err
        }

        dur, err := ` + timeParseDuration + `(str)
        if err != nil {
            return err
        }

        d.Duration = dur

        return nil
    }

    func (d Duration) MarshalJSON() ([]byte, error) {
        return ` + jsonMarshal + `(d.Duration.String())
    }

    type durationBetween struct {
        Lower    *Duration ` + common.StructTag(`json:"lower"`) + `
        Upper *Duration ` + common.StructTag(`json:"upper"`) + `
    }


    type durationValue interface {
        // *Duration
        // *durationBetween
    }`)

	g.P(`func (m *DurationMatcher) checkFull(duration *time.Duration) error {
        value, ok := m.Value.(*Duration)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a duration") + `
        }

        if *duration != value.Duration {
            return ` + common.FmtErrorf(g, "%s is not equal to expected %s", "*duration", "value.Duration") + `
        }

        return nil
    }

    func (m *DurationMatcher) checkLess(duration *time.Duration) error {
        value, ok := m.Value.(*Duration)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a duration") + `
        }

        if !(*duration <= value.Duration) {
            return ` + common.FmtErrorf(g, "%s is not less than %s", "*duration", "value.Duration") + `
        }

        return nil
    }

    func (m *DurationMatcher) checkGreater(duration *time.Duration) error {
        value, ok := m.Value.(*Duration)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a duration") + `
        }

        if !(*duration >= value.Duration) {
            return ` + common.FmtErrorf(g, "%s is not greater than than %s", "*duration", "value.Duration") + `
        }

        return nil
    }

    func (m *DurationMatcher) checkBetween(duration *time.Duration) error {
        value, ok := m.Value.(*durationBetween)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a duration") + `
        }

        if value.Upper == nil || value.Lower == nil {
            return ` + common.FmtErrorf(g, "value is nil") + `
        }

        if !(*duration <= value.Upper.Duration) {
            return ` + common.FmtErrorf(g, "%s is not less than %s", "*duration", "value.Upper.Duration") + `
        }

        if !(*duration >= value.Lower.Duration) {
            return ` + common.FmtErrorf(g, "%s is not greater than %s", "*duration", "value.Lower.Duration") + `
        }

        return nil
    }`)

	if err := matcher.Generate(g, f); err != nil {
		return err
	}

	return nil
}

var matcher = matcherscommon.MatcherGen{
	Name:                   "DurationMatcher",
	Type:                   "*durationpb.Duration",
	ValueField:             "durationValue",
	ValueFieldAlternatives: []string{"*Duration", "*durationBetween"},
	ConstructorOverrides: map[string]matcherscommon.ConstructorOverride{
		"Full": {
			Args: "value *Duration",
			Body: `return &DurationMatcher{
                Operator: opFull,
                Value: value,
            }`,
		},
		"Less": {
			Args: "value *Duration",
			Body: `return &DurationMatcher{
                Operator: opLess,
                Value: value,
            }`,
		},
		"Greater": {
			Args: "value *Duration",
			Body: `return &DurationMatcher{
                Operator: opGreater,
                Value: value,
            }`,
		},
		"Between": {
			Args: "lower *Duration, upper *Duration",
			Body: `return &DurationMatcher{
                Operator: opBetween,
                Value: &durationBetween {
                    Lower: lower,
                    Upper: upper,
                },
            }`,
		},
	},
	DefaultOperator:      "Full",
	AddConstructorSuffix: false,
	SkipMatch:            false,
	SkipMarshal:          false,
	SkipOperatorGen:      false,
	SkipStructGen:        false,
	SkipUnmarshal:        false,
	SkipConstructors:     false,
	OperatorFuncs: map[string]matcherscommon.GenerateMatchCase{
		"Full": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "duration is nil") + `
            }
            dur := value.AsDuration()
            return m.checkFull(&dur)`

			return res, nil
		},
		"Less": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "duration is nil") + `
            }
            dur := value.AsDuration()
            return m.checkLess(&dur)`

			return res, nil
		},
		"Greater": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "duration is nil") + `
            }
            dur := value.AsDuration()
            return m.checkGreater(&dur)`

			return res, nil
		},
		"Between": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "duration is nil") + `
            }
            dur := value.AsDuration()
            return m.checkBetween(&dur)`

			return res, nil
		},
	},
}
