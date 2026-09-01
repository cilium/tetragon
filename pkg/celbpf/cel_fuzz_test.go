// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package celbpf

import (
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"

	cgTypes "github.com/google/cel-go/common/types"
)

type exprArgs []any

func (as exprArgs) String() string {
	s := make([]string, 0, len(as))
	for _, a := range as {
		s = append(s, fmt.Sprintf("%v:%T", a, a))
	}
	return "{" + strings.Join(s, ",") + "}"
}

type randExprSt struct {
	r *rand.Rand
	// expressions budget
	nexprs int
	// available arguments
	args exprArgs
	// function / overload declarations
	fnOpts []fnOpts
}

func newRandExprSt(r *rand.Rand, nexprs int, nargs int) *randExprSt {
	argTypes := []func() any{
		func() any { return r.Uint64() },
		func() any { return r.Uint32() },
		func() any { return r.Int64() },
		func() any { return r.Int32() },
	}

	randomArg := func() any {
		return argTypes[r.IntN(len(argTypes))]()
	}

	args := make([]any, 0, nargs)
	for range nargs {
		args = append(args, randomArg())
	}

	return &randExprSt{
		r:      r,
		nexprs: nexprs,
		args:   args,
		fnOpts: getFnsOpts(),
	}
}

func (st *randExprSt) celNullaryExpr(ty *cgTypes.Type) string {
	var aidxs []any
	for idx, arg := range st.args {
		switch arg.(type) {
		case uint64:
			if ty == u64Ty {
				aidxs = append(aidxs, idx)
			}
		case uint32:
			if ty == u32Ty {
				aidxs = append(aidxs, idx)
			}
		case int64:
			if ty == s64Ty {
				aidxs = append(aidxs, idx)
			}
		case int32:
			if ty == s32Ty {
				aidxs = append(aidxs, idx)
			}
		default:
			panic(fmt.Sprintf("unhandled arg type: '%T'", arg))
		}
	}

	// if args of the requested exist, 50% of using args vs literals
	if len(aidxs) > 0 && st.r.UintN(2) >= 1 {
		ri := st.r.IntN(len(aidxs))
		return fmt.Sprintf("arg%d", aidxs[ri])
	}

	// otherwise generate a random literal value
	switch ty {
	case cgTypes.BoolType:
		switch st.r.UintN(2) {
		case 0:
			return "false"
		case 1:
			return "true"
		}
	case s64Ty:
		return strconv.FormatInt(st.r.Int64(), 10)
	case u64Ty:
		return fmt.Sprintf("%du", st.r.Uint64())
	case s32Ty:
		return fmt.Sprintf("int32(%d)", st.r.Int32())
	case u32Ty:
		return fmt.Sprintf("uint32(%du)", st.r.Uint32())
	}
	panic(fmt.Sprintf("unknown/unhandled type: %v", ty))
}

// Some of the types here are parametric, so make them concrete
func concretizeArgs(r *rand.Rand, tys []*cgTypes.Type) []*cgTypes.Type {

	allTys := []*cgTypes.Type{cgTypes.BoolType}
	for _, ity := range intTypes {
		allTys = append(allTys, ity.ty)
	}

	ret := make([]*cgTypes.Type, 0, len(tys))
	params := make(map[string]*cgTypes.Type)
	for _, ty := range tys {
		if ty.Kind() != cgTypes.TypeParamKind {
			ret = append(ret, ty)
			continue
		}

		name := ty.TypeName()
		if pty, ok := params[name]; ok {
			ret = append(ret, pty)
			continue
		}

		rty := allTys[r.IntN(len(allTys))]
		params[name] = rty
		ret = append(ret, rty)
	}

	return ret
}

// create a random CEL expression of result ty
func (st *randExprSt) celExpr(ty *cgTypes.Type) string {
	if st.nexprs == 0 {
		// no expression budget, generate nullary expression
		return st.celNullaryExpr(ty)
	}

	type candidate struct {
		fnName string
		args   []*cgTypes.Type
	}

	var candidates []candidate
	// search function overloads for a matching result type
	//
	// NB(kkourt): we are currently not handling parametric types, since we have no overloads
	// with parametric results, but if this changes we would need to modify the code here.
	for _, fn := range st.fnOpts {
		for _, over := range fn.overloads {
			if over.res == ty {
				candidates = append(candidates, candidate{fnName: fn.name, args: over.args})
			}
		}
	}

	// NB: this should not happen, but things might change as we add overloads/types, so panic
	// with reasonable message if it does.
	if len(candidates) == 0 {
		panic("celExpr: no candidates found")
	}

	// select a candidate
	cand := candidates[st.r.IntN((len(candidates)))]
	cand.args = concretizeArgs(st.r, cand.args)
	var args []string
	switch len(cand.args) {
	case 1:
		// candidate accepts one argument: create a new state with one expression less and
		// recurse
		newSt := randExprSt{
			r:      st.r,
			nexprs: st.nexprs - 1,
			args:   st.args,
			fnOpts: st.fnOpts,
		}
		args = []string{newSt.celExpr(cand.args[0])}
	case 2:
		// candidate accepts two arguments: create a two states with a total expression
		// budget one expression less than before, and recurse.
		nexprs1 := st.r.IntN(st.nexprs)
		nexprs2 := st.nexprs - 1 - nexprs1
		st1 := randExprSt{
			r:      st.r,
			nexprs: nexprs1,
			args:   st.args,
			fnOpts: st.fnOpts,
		}
		st2 := randExprSt{
			r:      st.r,
			nexprs: nexprs2,
			args:   st.args,
			fnOpts: st.fnOpts,
		}
		argTy1 := cand.args[0]
		arg1 := st1.celExpr(argTy1)
		arg2 := st2.celExpr(cand.args[1])
		args = []string{arg1, arg2}
	default:
		panic(fmt.Sprintf("unexpected cand: %+v", cand))
	}

	// For overloads such as !_, _=_, replace _ with generated terms
	if strings.Contains(cand.fnName, "_") {
		aargs := make([]any, 0, len(args))
		for _, arg := range args {
			aargs = append(aargs, arg)
		}
		f := strings.ReplaceAll(cand.fnName, "_", "(%s)")
		return fmt.Sprintf(f, aargs...)
	}

	// otherwise, call the function
	return fmt.Sprintf("%s(%s)", cand.fnName, strings.Join(args, ","))
}

func randCelExpr(s1, s2 uint64) (string, exprArgs) {
	rg := rand.NewPCG(s1, s2)
	st := newRandExprSt(rand.New(rg), 4, 3)
	expr := st.celExpr(cgTypes.BoolType)
	return expr, st.args
}

func FuzzCelExpr(f *testing.F) {
	if !Supported() {
		f.Skip()
	}
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(1), uint64(2))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, s1, s2 uint64) {
		s, args := randCelExpr(s1, s2)
		oracleRes := evalCEL(t, s, args)
		evalCELBPF(t, s, args, oracleRes)
	})
}
