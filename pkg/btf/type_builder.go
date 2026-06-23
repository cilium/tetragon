// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package btf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/cilium/tetragon/pkg/cursorparser"
)

type btfTypeParser struct {
	*cursorparser.Parser
	spec *btf.Spec
}

// ParseBTFType builds a BTF type from a C-like type expression.
//
// Supported constructs are primitive types and BTF spec types. For example:
//
//   - "char*"
//   - "(*char[64])"
//   - "uint64_t[4]"
//   - "struct task_struct *"
func ParseBTFType(spec *btf.Spec, typeExpr string) (btf.Type, error) {
	if spec == nil {
		return nil, errors.New("no BTF spec provided")
	}
	parser := btfTypeParser{Parser: cursorparser.New(typeExpr), spec: spec}
	ty, err := parser.parseType()
	if err != nil {
		return nil, err
	}
	if !parser.Done() {
		return nil, parser.errorf("unexpected token %q", parser.ReadRest())
	}
	return ty, nil
}

func (p *btfTypeParser) parseType() (btf.Type, error) {
	if p.Done() {
		return nil, p.errorf("empty type expression")
	}

	prefixPointers := 0
	for p.Consume('*') {
		prefixPointers++
	}

	ty, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for {
		switch {
		case p.Consume('*'):
			ty = &btf.Pointer{Target: ty}
		case p.Consume('['):
			nelems, err := p.parseArraySize()
			if err != nil {
				return nil, err
			}
			ty = &btf.Array{
				Type:   ty,
				Index:  arrayIndexType(),
				Nelems: nelems,
			}
		default:
			for range prefixPointers {
				ty = &btf.Pointer{Target: ty}
			}
			return ty, nil
		}
	}
}

func (p *btfTypeParser) parsePrimary() (btf.Type, error) {
	if p.Consume('(') {
		ty, err := p.parseType()
		if err != nil {
			return nil, err
		}
		if !p.Consume(')') {
			return nil, p.errorf("missing closing parenthesis")
		}
		return ty, nil
	}

	name := p.parseScalarName()
	if name == "" {
		return nil, p.errorf("expected type name")
	}
	ty, ok := primitiveBTFType(name)
	if ok {
		return ty, nil
	}
	ty, err := p.specBTFType(name)
	if err != nil {
		return nil, err
	}
	return ty, nil
}

func (p *btfTypeParser) specBTFType(name string) (btf.Type, error) {
	ty, err := lookupBTFTypeInSpec(p.spec, name)
	if err != nil {
		return nil, p.errorf("%v", err)
	}
	return ty, nil
}

func lookupBTFTypeInSpec(spec *btf.Spec, name string) (btf.Type, error) {
	if spec == nil {
		return nil, btf.ErrNotFound
	}

	if structName, ok := strings.CutPrefix(name, "struct "); ok {
		var st *btf.Struct
		if err := firstTypeByName(spec, structName, &st); err != nil {
			return nil, fmt.Errorf("failed to resolve struct %q from BTF spec: %w", structName, err)
		}
		return st, nil
	}

	if unionName, ok := strings.CutPrefix(name, "union "); ok {
		var union *btf.Union
		if err := firstTypeByName(spec, unionName, &union); err != nil {
			return nil, fmt.Errorf("failed to resolve union %q from BTF spec: %w", unionName, err)
		}
		return union, nil
	}

	if enumName, ok := strings.CutPrefix(name, "enum "); ok {
		var enum *btf.Enum
		if err := firstTypeByName(spec, enumName, &enum); err != nil {
			return nil, fmt.Errorf("failed to resolve enum %q from BTF spec: %w", enumName, err)
		}
		return enum, nil
	}

	return nil, fmt.Errorf("type %q is not supported", name)
}

func primitiveBTFType(name string) (btf.Type, bool) {
	switch name {
	case "void":
		return &btf.Void{}, true
	case "bool":
		return btfBool(), true
	case "char":
		return btfChar(), true

	// 1 Byte
	case "signed char", "int8", "int8_t", "s8", "__s8":
		return btfSignedInt("signed char", 1), true
	case "unsigned char", "uint8", "uint8_t", "u8", "__u8":
		return btfUnsignedInt("unsigned char", 1), true

	// 2 Bytes
	case "short", "short int", "signed short", "signed short int", "int16", "int16_t", "s16", "__s16":
		return btfSignedInt("short int", 2), true
	case "unsigned short", "unsigned short int", "uint16", "uint16_t", "u16", "__u16":
		return btfUnsignedInt("unsigned short int", 2), true

	// 4 Bytes
	case "int", "signed int", "signed", "int32", "int32_t", "s32", "__s32":
		return btfSignedInt("signed int", 4), true
	case "unsigned int", "unsigned", "uint32", "uint32_t", "u32", "__u32":
		return btfUnsignedInt("unsigned int", 4), true

	// 8 Bytes
	case "long", "long int", "signed long", "signed long int",
		"long long", "long long int", "signed long long", "signed long long int",
		"int64", "int64_t", "s64", "__s64":
		return btfSignedInt("signed long long int", 8), true
	case "unsigned long", "unsigned long int",
		"unsigned long long", "unsigned long long int",
		"uint64", "uint64_t", "u64", "__u64", "size_t":
		return btfUnsignedInt("unsigned long long int", 8), true

	default:
		return nil, false
	}
}

func btfBool() btf.Type {
	return &btf.Int{
		Name:     "bool",
		Size:     1,
		Encoding: btf.Bool,
	}
}

func btfChar() btf.Type {
	return &btf.Int{
		Name:     "char",
		Size:     1,
		Encoding: btf.Char,
	}
}

func btfSignedInt(name string, size uint32) btf.Type {
	return &btf.Int{
		Name:     name,
		Size:     size,
		Encoding: btf.Signed,
	}
}

func btfUnsignedInt(name string, size uint32) btf.Type {
	return &btf.Int{
		Name:     name,
		Size:     size,
		Encoding: btf.Unsigned,
	}
}

func (p *btfTypeParser) parseScalarName() string {
	raw := p.ReadUntilAny("*[]()")
	return strings.Join(strings.Fields(strings.ToLower(raw)), " ")
}

func (p *btfTypeParser) parseArraySize() (uint32, error) {
	sizeLiteral, ok := p.ReadUntil(']')
	if !ok {
		return 0, p.errorf("missing closing array bracket")
	}
	sizeLiteral = strings.TrimSpace(sizeLiteral)
	if sizeLiteral == "" {
		return 0, p.errorf("missing array size")
	}
	if !p.Consume(']') {
		return 0, p.errorf("missing closing array bracket")
	}
	n, err := strconv.ParseUint(sizeLiteral, 10, 32)
	if err != nil {
		return 0, p.errorf("invalid array size %q", sizeLiteral)
	}
	return uint32(n), nil
}

func (p *btfTypeParser) errorf(format string, args ...any) error {
	return fmt.Errorf("parse BTF type %q at byte %d: %s", p.Input(), p.Pos(),
		fmt.Sprintf(format, args...))
}

func arrayIndexType() btf.Type {
	return &btf.Int{
		Name:     "unsigned int",
		Size:     4,
		Encoding: btf.Unsigned,
	}
}
