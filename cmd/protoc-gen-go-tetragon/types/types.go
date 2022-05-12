// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package types

import "google.golang.org/protobuf/compiler/protogen"

const (
	WrappersPath  = protogen.GoImportPath("google.golang.org/protobuf/types/known/wrapperspb")
	TimestampPath = protogen.GoImportPath("google.golang.org/protobuf/types/known/timestamppb")
	DurationPath  = protogen.GoImportPath("google.golang.org/protobuf/types/known/durationpb")
)
