// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package generate

import (
	"fmt"

	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/eventchecker"
	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/helpers"
	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/types"
	"google.golang.org/protobuf/compiler/protogen"
)

type GeneratorFunc func(gen *protogen.Plugin, files []*protogen.File) error

var Generators = []GeneratorFunc{
	helpers.Generate,
	eventchecker.Generate,
	types.Generate,
}

func Generate() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		for _, generator := range Generators {
			if err := generator(gen, gen.Files); err != nil {
				return fmt.Errorf("failed to generate file: %w", err)
			}
		}
		return nil
	})
}
