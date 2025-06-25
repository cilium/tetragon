// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventchecker

import (
	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/common"
	"github.com/jpillora/longestcommon"
	"google.golang.org/protobuf/compiler/protogen"
)

type Enum protogen.Enum

func (enum *Enum) Generate(g *protogen.GeneratedFile) error {
	enumIdent := common.TetragonAPIIdent(g, enum.GoIdent.GoName)
	g.P(`// ` + enum.checkerName() + ` checks a ` + enumIdent + `
    type ` + enum.checkerName() + ` ` + enumIdent)

	if err := enum.generateMarshal(g); err != nil {
		return err
	}

	if err := enum.generateUnmarshal(g); err != nil {
		return err
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := enum.generateChecker(g); err != nil {
		return err
	}

	return nil
}

func (enum *Enum) generateChecker(g *protogen.GeneratedFile) error {
	targetIdent := common.TetragonAPIIdent(g, enum.GoIdent.GoName)

	g.P(`// New` + enum.checkerName() + ` creates a new ` + enum.checkerName() + `
    func New` + enum.checkerName() + `(val ` + targetIdent + `) *` + enum.checkerName() + ` {
        enum := ` + enum.checkerName() + `(val)
        return &enum
    }
    `)

	// 	g.P(`// WithValue configures the ` + enum.checkerName() + ` to check a value
	//     func (enum *` + enum.checkerName() + `) WithValue(val ` + targetIdent + `) *` + enum.checkerName() + ` {
	//         *enum = ` + enum.checkerName() + `(val)
	//         return enum
	//     }
	//     `)

	g.P(`// Check checks a ` + enum.GoIdent.GoName + ` against the checker
    func (enum *` + enum.checkerName() + `) Check( val *` + targetIdent + `) error {
        if val == nil {
            return ` + common.FmtErrorf(g, enum.checkerName()+": "+enum.GoIdent.GoName+" is nil and does not match expected value %s", targetIdent+"(*enum)") + `
        }
        if *enum != ` + enum.checkerName() + `(*val) {
            return ` + common.FmtErrorf(g, enum.checkerName()+": "+enum.GoIdent.GoName+" has value %s which does not match expected value %s", "(*val)", targetIdent+"(*enum)") + `
        }
        return nil
    }`)

	return nil
}

func (enum *Enum) generateMarshal(g *protogen.GeneratedFile) error {
	jsonMarshal := common.GoIdent(g, "encoding/json", "Marshal")
	stringsTrimPrefix := common.GoIdent(g, "strings", "TrimPrefix")
	nameMap := common.TetragonAPIIdent(g, enum.GoIdent.GoName+"_name")

	longestPrefix := getLongestPreifx(enum)

	g.P(`// MarshalJSON implements json.Marshaler interface
    func (enum ` + enum.checkerName() + `) MarshalJSON() ([]byte, error) {
        if name, ok := ` + nameMap + `[int32(enum)]; ok {
            name = ` + stringsTrimPrefix + `(name, "` + longestPrefix + `")
            return ` + jsonMarshal + `(name)
        }

        return nil, ` + common.FmtErrorf(g, "Unknown "+enum.GoIdent.GoName+" %d", "enum") + `
    }
    `)

	return nil
}

func (enum *Enum) generateUnmarshal(g *protogen.GeneratedFile) error {
	// We want to use yaml.UnmarshalStrict here since it will complain about unknown fields
	yamlUnmarshal := common.GoIdent(g, "sigs.k8s.io/yaml", "UnmarshalStrict")
	stringsToUpper := common.GoIdent(g, "strings", "ToUpper")
	valueMap := common.TetragonAPIIdent(g, enum.GoIdent.GoName+"_value")

	longestPrefix := getLongestPreifx(enum)

	g.P(`// UnmarshalJSON implements json.Unmarshaler interface
    func (enum *` + enum.checkerName() + `) UnmarshalJSON(b []byte) error {
        var str string
        if err := ` + yamlUnmarshal + `(b, &str); err != nil {
            return err
        }

        // Convert to uppercase if not already
        str = ` + stringsToUpper + `(str)

        // Look up the value from the enum values map
        if n, ok := ` + valueMap + `[str]; ok {
            *enum = ` + enum.checkerName() + `(n)
        } else if n, ok := ` + valueMap + `["` + longestPrefix + `" + str]; ok {
            *enum = ` + enum.checkerName() + `(n)
        } else {
            return ` + common.FmtErrorf(g, "Unknown "+enum.GoIdent.GoName+" %s", "str") + `
        }

        return nil
    }`)

	return nil
}

func (enum *Enum) checkerName() string {
	return enum.GoIdent.GoName + "Checker"
}

func getLongestPreifx(enum *Enum) string {
	var valueNames []string
	for _, value := range enum.Values {
		valueNames = append(valueNames, string(value.Desc.Name()))
	}
	longestPrefix := longestcommon.Prefix(valueNames)

	// DAC_OVERRIDE messes everything up, so set capabilities prefix manually
	if enum.GoIdent.GoName == "CapabilitiesType" {
		longestPrefix = "CAP_"
	}

	return longestPrefix
}
