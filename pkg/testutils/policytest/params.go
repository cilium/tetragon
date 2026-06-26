// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"iter"
)

func (p *Parameter) values() iter.Seq[any] {
	return func(yield func(any) bool) {
		if len(p.Values) == 0 {
			yield(p.Default)
			return
		}

		for _, v := range p.Values {
			if !yield(v) {
				return
			}
		}
	}
}

func allParamValues(ps []Parameter) iter.Seq[ParamVals] {
	return func(yield func(ParamVals) bool) {
		if len(ps) == 0 {
			yield(newParamVals())
			return
		}

		param := ps[0]
		for vals := range allParamValues(ps[1:]) {
			for val := range param.values() {
				vals[param.Name] = val
				if !yield(vals) {
					return
				}
			}
		}
	}
}
