//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package main

import (
	"fmt"

	"github.com/isovalent/tetragon-oss/cmd/protoc-gen-go-tetragon/eventcache"
	"github.com/isovalent/tetragon-oss/cmd/protoc-gen-go-tetragon/filters"
	"github.com/isovalent/tetragon-oss/cmd/protoc-gen-go-tetragon/helpers"
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
