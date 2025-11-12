// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CEL -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"fmt"

	cgChecker "github.com/google/cel-go/checker"
	cgContainers "github.com/google/cel-go/common/containers"
)

func newCheckerEnv() (*cgChecker.Env, error) {
	tyProvider, err := NewProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize type provider: %w", err)
	}
	checkerEnv, err := cgChecker.NewEnv(cgContainers.DefaultContainer, tyProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize environment: %w", err)
	}

	//TODO:
	// checkerEnv.AddFunctions()
	//checkerEnv.AddIdents()

	return checkerEnv, nil

}
