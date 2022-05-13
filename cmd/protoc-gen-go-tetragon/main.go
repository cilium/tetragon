// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventcache"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/filters"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/helpers"
	"google.golang.org/protobuf/compiler/protogen"
)

func main() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		for _, f := range gen.Files {
			if !f.Generate {
				continue
			}
			err := generate(gen, f)
			if err != nil {
				return fmt.Errorf("Failed to generate file %s: %v", f.Desc.Name(), err)
			}
		}
		return nil
	})
}

// generate is the main entrypoint for codegen. All Generate() funcs should be called
// here.
func generate(gen *protogen.Plugin, f *protogen.File) error {
	if err := eventcache.Generate(gen, f); err != nil {
		return err
	}
	if err := filters.Generate(gen, f); err != nil {
		return err
	}
	if err := helpers.Generate(gen, f); err != nil {
		return err
	}
	return nil
}
