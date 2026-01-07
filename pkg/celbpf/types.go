// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CEL -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>

package celbpf

import (
	"errors"
	"fmt"

	gt "github.com/cilium/tetragon/pkg/generictypes"

	cgTypes "github.com/google/cel-go/common/types"
)

var (
	s64Ty = cgTypes.IntType
	u64Ty = cgTypes.UintType
	s32Ty = cgTypes.NewOpaqueType("s32")
	u32Ty = cgTypes.NewOpaqueType("u32")
)

type exprArg struct {
	ty        *cgTypes.Type
	argOffset int
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

func newExprArg(arg ExprArg) (exprArg, error) {
	ty, err := typeFromGenTy(arg.GenTy)
	if err != nil {
		return exprArg{}, err
	}
	return exprArg{
		ty:        ty,
		argOffset: arg.ArgOffset,
	}, nil
}
