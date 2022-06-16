// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package matchers

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/bytesmatcher"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/durationmatcher"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/listmatcher"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventchecker/matchers/timestampmatcher"
	"google.golang.org/protobuf/compiler/protogen"
)

func Generate(gen *protogen.Plugin, f *protogen.File) error {
	if err := bytesmatcher.Generate(gen, f); err != nil {
		return fmt.Errorf("Failed to generate BytesMatcher: %w", err)
	}

	if err := timestampmatcher.Generate(gen, f); err != nil {
		return fmt.Errorf("Failed to generate TimestampMatcher: %w", err)
	}

	if err := durationmatcher.Generate(gen, f); err != nil {
		return fmt.Errorf("Failed to generate DurationMatcher: %w", err)
	}

	if err := listmatcher.Generate(gen, f); err != nil {
		return fmt.Errorf("Failed to generate ListMatcher: %w", err)
	}

	return nil
}
