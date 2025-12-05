// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CEL -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>

package celbpf

import (
	cgTypes "github.com/google/cel-go/common/types"
)

var (
	s64Ty = cgTypes.IntType
	u64Ty = cgTypes.UintType
	s32Ty = cgTypes.NewOpaqueType("s32")
	u32Ty = cgTypes.NewOpaqueType("u32")
)
