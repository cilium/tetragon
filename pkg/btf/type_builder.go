// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package btf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
)

type btfTypeParser struct {
	expr string
	pos  int
	spec *btf.Spec
}

// Thread-safe lazy cache for the fallback BTF spec to avoid re-parsing vmlinux repeatedly.
var (
	fallbackSpecInit sync.Once
	fallbackSpec     *btf.Spec
	errFallbackSpec  error
)

var loadFallbackBTFSpec = func() (*btf.Spec, error) {
	fallbackSpecInit.Do(func() {
		fallbackSpec, errFallbackSpec = NewBTF()
	})
	return fallbackSpec, errFallbackSpec
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
	parser := btfTypeParser{expr: typeExpr, spec: spec}
	ty, err := parser.parseType()
	if err != nil {
		return nil, err
	}
	parser.skipSpace()
	if !parser.done() {
		return nil, parser.errorf("unexpected token %q", parser.expr[parser.pos:])
	}
	return ty, nil
}

func (p *btfTypeParser) parseType() (btf.Type, error) {
	p.skipSpace()
	if p.done() {
		return nil, p.errorf("empty type expression")
	}

	prefixPointers := 0
	for p.consume('*') {
		prefixPointers++
	}

	ty, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for {
		switch {
		case p.consume('*'):
			ty = &btf.Pointer{Target: ty}
		case p.consume('['):
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
	p.skipSpace()
	if p.consume('(') {
		ty, err := p.parseType()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if !p.consume(')') {
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
	if err == nil {
		return ty, nil
	}
	if p.spec != nil && !errors.Is(err, btf.ErrNotFound) {
		return nil, p.errorf("%v", err)
	}

	spec, loadErr := loadFallbackBTFSpec()
	if loadErr != nil {
		return nil, p.errorf("failed to load fallback BTF spec for type %q: %v", name, loadErr)
	}
	p.spec = spec

	ty, err = lookupBTFTypeInSpec(p.spec, name)
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
	case "signed char", "int8", "int8_t", "s8", "__s8":
		return btfSignedInt("int8_t", 1), true
	case "unsigned char", "uint8", "uint8_t", "u8", "__u8":
		return btfUnsignedInt("uint8_t", 1), true
	case "short", "short int", "signed short", "signed short int", "int16", "int16_t", "s16", "__s16":
		return btfSignedInt("int16_t", 2), true
	case "unsigned short", "unsigned short int", "uint16", "uint16_t", "u16", "__u16":
		return btfUnsignedInt("uint16_t", 2), true
	case "int", "signed int", "signed", "int32", "int32_t", "s32", "__s32":
		return btfSignedInt("int32_t", 4), true
	case "unsigned int", "unsigned", "uint32", "uint32_t", "u32", "__u32":
		return btfUnsignedInt("uint32_t", 4), true
	case "long", "long int", "signed long", "signed long int",
		"long long", "long long int", "signed long long", "signed long long int",
		"int64", "int64_t", "s64", "__s64":
		return btfSignedInt("int64_t", 8), true
	case "unsigned long", "unsigned long int",
		"unsigned long long", "unsigned long long int",
		"uint64", "uint64_t", "u64", "__u64", "size_t":
		return btfUnsignedInt("uint64_t", 8), true
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
	start := p.pos
	for !p.done() {
		r := rune(p.expr[p.pos])
		if r == '*' || r == '[' || r == ']' || r == '(' || r == ')' {
			break
		}
		p.pos++
	}
	return strings.Join(strings.Fields(strings.ToLower(p.expr[start:p.pos])), " ")
}

func (p *btfTypeParser) parseArraySize() (uint32, error) {
	p.skipSpace()
	start := p.pos
	for !p.done() {
		b := p.expr[p.pos]
		if b >= '0' && b <= '9' {
			p.pos++
		} else {
			break
		}
	}
	if start == p.pos {
		return 0, p.errorf("missing array size")
	}
	sizeLiteral := p.expr[start:p.pos]

	if !p.consume(']') {
		return 0, p.errorf("missing closing array bracket")
	}
	n, err := strconv.ParseUint(sizeLiteral, 10, 32)
	if err != nil {
		return 0, p.errorf("invalid array size %q", sizeLiteral)
	}
	return uint32(n), nil
}

func (p *btfTypeParser) skipSpace() {
	for !p.done() {
		b := p.expr[p.pos]
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f' {
			p.pos++
		} else {
			break
		}
	}
}

func (p *btfTypeParser) consume(ch byte) bool {
	p.skipSpace()
	if p.done() || p.expr[p.pos] != ch {
		return false
	}
	p.pos++
	return true
}

func (p *btfTypeParser) done() bool {
	return p.pos >= len(p.expr)
}

func (p *btfTypeParser) errorf(format string, args ...any) error {
	return fmt.Errorf("parse BTF type %q at byte %d: %s", p.expr, p.pos,
		fmt.Sprintf(format, args...))
}

func arrayIndexType() btf.Type {
	return &btf.Int{
		Name:     "unsigned int",
		Size:     4,
		Encoding: btf.Unsigned,
	}
}
