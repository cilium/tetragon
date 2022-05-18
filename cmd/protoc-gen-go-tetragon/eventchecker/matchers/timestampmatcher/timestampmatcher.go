// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package timestampmatcher

import (
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/matcherscommon"
	"google.golang.org/protobuf/compiler/protogen"
)

func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewGeneratedFile(gen, f, "eventchecker/matchers/timestampmatcher")

	// Force an import of timestamppb.Timestamp
	common.GoIdent(g, "google.golang.org/protobuf/types/known/timestamppb", "Timestamp")

	timeRFC3339 := common.GoIdent(g, "time", "RFC3339")
	timeTime := common.GoIdent(g, "time", "Time")
	timeParse := common.GoIdent(g, "time", "Parse")
	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")

	g.P(`var formats = []string{
        ` + timeRFC3339 + `,
        "2006-01-02T15:04:05.999999999Z",
        "2006-01-02T15:04:05.999999999",
        "2006-01-02T15:04:05Z",
        "2006-01-02T15:04:05",
    }

    type Time struct {
        ` + timeTime + `
    }

    func (t *Time) UnmarshalJSON(b []byte) error {
        var s string
        err := ` + yamlUnmarshal + `(b, &s)
        if err != nil {
            return err
        }

        for _, format := range formats {
            t_, err := ` + timeParse + `(format, s)
            if err == nil {
                t.Time = t_.UTC()
                return nil
            }
        }

        return ` + common.FmtErrorf(g, "Unmarshal Time: Failed to parse time %s as RFC3339", "s") + `
    }


    type timestampBetween struct {
        After  *Time ` + common.StructTag(`json:"after"`) + `
        Before *Time ` + common.StructTag(`json:"before"`) + `
    }

    type timestampFormat struct {
        Format    string ` + common.StructTag(`json:"format"`) + `
        Timestamp *Time  ` + common.StructTag(`json:"time"`) + `
    }

    type timestampValue interface {
        // *Time
        // *timestampBetween
        // *timestampFormat
    }`)

	g.P(`func (m *TimestampMatcher) checkDay(ts *` + timeTime + `) error {
        value, ok := m.Value.(*Time)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestamp") + `
        }

        tsYear := ts.Year()
        tcYear := value.Year()

        if tsYear != tcYear {
            return ` + common.FmtErrorf(g, "year %04d does not match expected %04d", "tsYear", "tcYear") + `
        }

        tsMonth := ts.Month()
        tcMonth := value.Month()

        if tsMonth != tcMonth {
            return ` + common.FmtErrorf(g, "month %02d does not match expected %02d", "tsMonth", "tcMonth") + `
        }

        tsDay := ts.Day()
        tcDay := value.Day()

        if tsDay != tcDay {
            return ` + common.FmtErrorf(g, "day %02d does not match expected %02d", "tsDay", "tcDay") + `
        }

        return nil
    }

    func (m *TimestampMatcher) checkHour(ts *` + timeTime + `) error {
        value, ok := m.Value.(*Time)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestamp") + `
        }

        if err := m.checkDay(ts); err != nil {
            return err
        }

        tsHour := ts.Hour()
        tcHour := value.Hour()

        if tsHour != tcHour {
            return ` + common.FmtErrorf(g, "hour %02d does not match expected %02d", "tsHour", "tcHour") + `
        }

        return nil
    }

    func (m *TimestampMatcher) checkMinute(ts *` + timeTime + `) error {
        value, ok := m.Value.(*Time)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestamp") + `
        }

        if err := m.checkHour(ts); err != nil {
            return err
        }

        tsMinute := ts.Minute()
        tcMinute := value.Minute()

        if tsMinute != tcMinute {
            return ` + common.FmtErrorf(g, "minute %d does not match expected %d", "tsMinute", "tcMinute") + `
        }

        return nil
    }

    func (m *TimestampMatcher) checkSecond(ts *` + timeTime + `) error {
        value, ok := m.Value.(*Time)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestamp") + `
        }

        if err := m.checkMinute(ts); err != nil {
            return err
        }

        tsSecond := ts.Second()
        tcSecond := value.Second()

        if tsSecond != tcSecond {
            return ` + common.FmtErrorf(g, "second %d does not match expected %d", "tsSecond", "tcSecond") + `
        }

        return nil
    }

    func (m *TimestampMatcher) checkBefore(ts *` + timeTime + `) error {
        value, ok := m.Value.(*Time)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestamp") + `
        }

        tsTime := ts
        tcTime := value.Time

        if !(tsTime.Before(tcTime) || tsTime.Equal(tcTime)) {
            return ` + common.FmtErrorf(g, "%s is not before %s", "tsTime", "tcTime") + `
        }

        return nil
    }

    func (m *TimestampMatcher) checkAfter(ts *` + timeTime + `) error {
        value, ok := m.Value.(*Time)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestamp") + `
        }

        tsTime := ts
        tcTime := value.Time

        if !(tsTime.After(tcTime) || tsTime.Equal(tcTime)) {
            return ` + common.FmtErrorf(g, "%s is not after %s", "tsTime", "tcTime") + `
        }

        return nil
    }

    func (m *TimestampMatcher) checkBetween(ts *` + timeTime + `) error {
        value, ok := m.Value.(*timestampBetween)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestampBetween") + `
        }

        if value.Before == nil || value.After == nil {
            return ` + common.FmtErrorf(g, "value is nil") + `
        }

        tsTime := ts
        beforeTime := value.Before.Time
        afterTime := value.After.Time

        isBefore := tsTime.Before(beforeTime) || tsTime.Equal(beforeTime)
        isAfter := tsTime.After(afterTime) || tsTime.Equal(afterTime)

        if !(isBefore) {
            return ` + common.FmtErrorf(g, "%s is not before %s", "tsTime", "beforeTime") + `
        }

        if !(isAfter) {
            return ` + common.FmtErrorf(g, "%s is not after %s", "tsTime", "afterTime") + `
        }

        return nil
    }

    func (m *TimestampMatcher) checkFormat(ts *` + timeTime + `) error {
        value, ok := m.Value.(*timestampFormat)
        if !ok {
            return ` + common.FmtErrorf(g, "value is not a timestampFormat") + `
        }

        if value.Timestamp == nil {
            return ` + common.FmtErrorf(g, "value is nil") + `
        }

        tsStr := ts.Format(value.Format)
        tcStr := value.Timestamp.Format(value.Format)

        if tcStr != tsStr {
            return ` + common.FmtErrorf(g, "%s does not match expected %s", "tsStr", "tcStr") + `
        }

        return nil
    }`)

	if err := matcher.Generate(g, f); err != nil {
		return err
	}

	return nil
}

var matcher = matcherscommon.MatcherGen{
	Name:                   "TimestampMatcher",
	Type:                   "*timestamppb.Timestamp",
	ValueField:             "timestampValue",
	ValueFieldAlternatives: []string{"*Time", "*timestampBetween", "*timestampFormat"},
	ConstructorOverrides: map[string]matcherscommon.ConstructorOverride{
		"Day": {
			Args: "value *Time",
			Body: `return &TimestampMatcher{
                Operator: opDay,
                Value: value,
            }`,
		},
		"Hour": {
			Args: "value *Time",
			Body: `return &TimestampMatcher{
                Operator: opHour,
                Value: value,
            }`,
		},
		"Minute": {
			Args: "value *Time",
			Body: `return &TimestampMatcher{
                Operator: opMinute,
                Value: value,
            }`,
		},
		"Second": {
			Args: "value *Time",
			Body: `return &TimestampMatcher{
                Operator: opSecond,
                Value: value,
            }`,
		},
		"Before": {
			Args: "value *Time",
			Body: `return &TimestampMatcher{
                Operator: opBefore,
                Value: value,
            }`,
		},
		"After": {
			Args: "value *Time",
			Body: `return &TimestampMatcher{
                Operator: opAfter,
                Value: value,
            }`,
		},
		"Between": {
			Args: "before *Time, after *Time",
			Body: `return &TimestampMatcher{
                Operator: opBetween,
                Value: &timestampBetween{
                    After: after,
                    Before: before,
                },
            }`,
		},
		"Format": {
			Args: "value *Time, format string",
			Body: `return &TimestampMatcher{
                Operator: opFormat,
                Value: &timestampFormat{
                    Timestamp: value,
                    Format: format,
                },
            }`,
		},
	},
	DefaultOperator:      "Second",
	AddConstructorSuffix: false,
	SkipMatch:            false,
	SkipMarshal:          false,
	SkipOperatorGen:      false,
	SkipStructGen:        false,
	SkipUnmarshal:        false,
	SkipConstructors:     false,
	OperatorFuncs: map[string]matcherscommon.GenerateMatchCase{
		"Day": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkDay(&tsTime)`

			return res, nil
		},
		"Hour": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkHour(&tsTime)`

			return res, nil
		},
		"Minute": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkMinute(&tsTime)`

			return res, nil
		},
		"Second": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkSecond(&tsTime)`

			return res, nil
		},
		"Before": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkBefore(&tsTime)`

			return res, nil
		},
		"After": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkAfter(&tsTime)`

			return res, nil
		},
		"Between": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkBetween(&tsTime)`

			return res, nil
		},
		"Format": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			res := `if m.Value == nil {
                return ` + common.FmtErrorf(g, "matcher value is nil") + `
            }
            if value == nil {
                return ` + common.FmtErrorf(g, "timestamp is nil") + `
            }
            tsTime := value.AsTime().UTC()
            return m.checkFormat(&tsTime)`

			return res, nil
		},
	},
}
