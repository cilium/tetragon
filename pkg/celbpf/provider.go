// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	cgTypes "github.com/google/cel-go/common/types"
	cgRef "github.com/google/cel-go/common/types/ref"
)

type Provider struct{}

func NewProvider() (*Provider, error) {
	return &Provider{}, nil
}

func (p *Provider) EnumValue(_ string) cgRef.Val {
	return cgTypes.NewErr("enum is not supported")
}

func (p *Provider) FindIdent(_ string) (cgRef.Val, bool) {
	return cgTypes.NewErr("ident is not supported"), false
}

func (p *Provider) FindStructType(_ string) (*cgTypes.Type, bool) {
	return nil, false
}

func (p *Provider) FindStructFieldNames(_ string) ([]string, bool) {
	return nil, false
}

func (p *Provider) NewValue(_ string, _ map[string]cgRef.Val) cgRef.Val {
	return nil
}

func (p *Provider) FindStructFieldType(_, _ string) (*cgTypes.FieldType, bool) {
	return nil, false
}
