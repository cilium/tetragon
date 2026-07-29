// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CEL -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>

package celbpf

import (
	"errors"
	"fmt"

	gt "github.com/cilium/tetragon/pkg/generictypes"

	cgDecls "github.com/google/cel-go/common/decls"
	cgTypes "github.com/google/cel-go/common/types"
)

var (
	s64Ty         = cgTypes.IntType
	u64Ty         = cgTypes.UintType
	s32Ty         = cgTypes.NewOpaqueType("s32")
	u32Ty         = cgTypes.NewOpaqueType("u32")
	boolTy        = cgTypes.BoolType
	unsupportedTy = cgTypes.NewOpaqueType("unsupported")
)

type intType struct {
	ty *cgTypes.Type
}

func (it *intType) opSuffix() string {
	switch it.ty {
	case s64Ty:
		return "s64"
	case u64Ty:
		return "u64"
	case s32Ty:
		return "s32"
	case u32Ty:
		return "u32"
	}

	panic(fmt.Sprintf("opSuffix: unknown type: %v", it.ty))
}

func (it *intType) overloadOp(op string) string {
	return op + "_" + it.opSuffix()
}

var intTypes = []intType{
	{s64Ty},
	{s32Ty},
	{u64Ty},
	{u32Ty},
}

func intCmpOperatorFnOpts(op string) []cgDecls.FunctionOpt {
	ret := make([]cgDecls.FunctionOpt, 0, len(intTypes))
	for _, ity := range intTypes {
		ret = append(ret, cgDecls.Overload(
			ity.overloadOp(op),
			[]*cgTypes.Type{ity.ty, ity.ty}, cgTypes.BoolType,
		))
	}
	return ret
}

func intBinaryOperatorFnOpts(op string) []cgDecls.FunctionOpt {
	ret := make([]cgDecls.FunctionOpt, 0, len(intTypes))
	for _, ity := range intTypes {
		ret = append(ret, cgDecls.Overload(
			ity.overloadOp(op),
			[]*cgTypes.Type{ity.ty, ity.ty}, ity.ty,
		))
	}
	return ret
}

func typeFromGenTy(genTy int) (*cgTypes.Type, error) {
	switch genTy {
	case gt.GenericS64Type:
		return s64Ty, nil
	case gt.GenericS32Type, gt.GenericIntType:
		return s32Ty, nil
	case gt.GenericU64Type:
		return u64Ty, nil
	case gt.GenericU32Type:
		return u32Ty, nil
	case gt.GenericInvalidType:
		return nil, errors.New("cannot convert invalid generic type")
	}

	return nil, fmt.Errorf("unhandled generic type: %d (%s)", genTy, gt.GenericTypeString(genTy))
}
