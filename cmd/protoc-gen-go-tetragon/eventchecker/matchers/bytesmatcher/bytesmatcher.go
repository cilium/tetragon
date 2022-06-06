// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bytesmatcher

import (
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/matcherscommon"
	"google.golang.org/protobuf/compiler/protogen"
)

func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewCodegenFile(gen, f, "eventchecker/matchers/bytesmatcher")

	if err := matcher.Generate(g, f); err != nil {
		return err
	}

	return nil
}

var matcher = matcherscommon.MatcherGen{
	Name:                   "BytesMatcher",
	Type:                   "[]byte",
	ValueField:             "[]byte",
	ValueFieldAlternatives: []string{},
	DefaultOperator:        "Full",
	AddConstructorSuffix:   false,
	SkipMatch:              false,
	SkipMarshal:            false,
	SkipOperatorGen:        false,
	SkipStructGen:          false,
	SkipUnmarshal:          false,
	SkipConstructors:       false,
	OperatorFuncs: map[string]matcherscommon.GenerateMatchCase{
		"Full": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			bytesEqual := common.GoIdent(g, "bytes", "Equal")

			res := `if ` + bytesEqual + `(value, m.Value) {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%v' does not match full '%v'", "value", "m.Value")

			return res, nil
		},
		"Prefix": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			bytesPrefix := common.GoIdent(g, "bytes", "HasPrefix")

			res := `if ` + bytesPrefix + `(value, m.Value) {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%v' does not have prefix '%v'", "value", "m.Value")

			return res, nil
		},
		"Suffix": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			bytesSuffix := common.GoIdent(g, "bytes", "HasSuffix")

			res := `if ` + bytesSuffix + `(value, m.Value) {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%v' does not have suffix '%v'", "value", "m.Value")

			return res, nil
		},
		"Contains": func(g *protogen.GeneratedFile, f *protogen.File) (string, error) {
			bytesContains := common.GoIdent(g, "bytes", "Contains")

			res := `if ` + bytesContains + `(value, m.Value) {
                return nil
            }
            return ` + common.FmtErrorf(g, "'%v' does not contain '%v'", "value", "m.Value")

			return res, nil
		},
	},
}
