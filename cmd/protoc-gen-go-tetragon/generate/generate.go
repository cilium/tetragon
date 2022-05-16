// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package generate

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventcache"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/filters"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/helpers"
	"google.golang.org/protobuf/compiler/protogen"
)

type GeneratorFunc func(gen *protogen.Plugin, f *protogen.File) error

var Generators = []GeneratorFunc{
	eventcache.Generate,
	filters.Generate,
	helpers.Generate,
}

func Generate() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		for _, f := range gen.Files {
			if !f.Generate {
				continue
			}

			for _, generator := range Generators {
				if err := generator(gen, f); err != nil {
					return fmt.Errorf("Failed to generate file %s: %v", f.Desc.Name(), err)
				}
			}
		}
		return nil
	})
}
