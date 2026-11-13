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

// ParseBTFType parses a type expression string into a BTF type.
//
// Type names can be primitives ("void", "bool", "char" and the integer names of
// the policy "type:" field, see primitiveBTFType), typedef names, or BTF spec
// types prefixed with their kind keyword ("struct task_struct", "union foo",
// "enum bar"). For primitive types, the spec is not required.
//
// ParseBTFType supports two modifiers, `*` for pointers and `[N]` for
// fixed-size arrays. Modifiers follow the type name and apply left to right.
// For example, "char*[4]" is an array of 4 char pointers and "char[4]*" is a
// pointer to an array of 4 chars.
//
// Examples:
//
//   - "char*"
//   - "uint64[4]"
//   - "struct task_struct *"
func ParseBTFType(spec *btf.Spec, typeExpr string) (btf.Type, error) {
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
			return ty, nil
		}
	}
}

func (p *btfTypeParser) parsePrimary() (btf.Type, error) {
	name := p.parseScalarName()
	if name == "" {
		return nil, p.errorf("expected type name")
	}

	// Kind-prefixed names can only come from the spec, so a primitive lookup
	// failure would only add noise to the error.
	if hasKindPrefix(name) {
		return p.specBTFType(name)
	}

	ty, err1 := p.primitiveBTFType(name)
	if err1 == nil {
		return ty, nil
	}

	ty, err2 := p.specBTFType(name)
	if err2 == nil {
		return ty, nil
	}

	return nil, errors.Join(err1, err2)
}

func hasKindPrefix(name string) bool {
	for _, prefix := range []string{"struct ", "union ", "enum "} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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
		return nil, fmt.Errorf("type %q requires a BTF spec: no BTF spec provided", name)
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

	var td *btf.Typedef
	if err := firstTypeByName(spec, name, &td); err == nil {
		return td, nil
	} else if errors.Is(err, btf.ErrNotFound) {
		return nil, fmt.Errorf("failed to resolve typedef %q from BTF spec: %w", name, err)
	}

	return nil, fmt.Errorf("type %q is not supported", name)
}

func (p *btfTypeParser) primitiveBTFType(name string) (btf.Type, error) {
	switch name {
	case "void":
		return &btf.Void{}, nil
	case "bool":
		return btfBool(), nil
	case "char":
		return btfChar(), nil

	// We support the same set of integer types as the policy "type:" field.

	// 1 byte
	case "int8", "sint8":
		return btfSignedInt(name, 1), nil
	case "uint8":
		return btfUnsignedInt(name, 1), nil

	// 2 bytes
	case "int16", "sint16":
		return btfSignedInt(name, 2), nil
	case "uint16":
		return btfUnsignedInt(name, 2), nil

	// 4 bytes
	case "int", "int32", "sint32":
		return btfSignedInt(name, 4), nil
	case "uint32":
		return btfUnsignedInt(name, 4), nil

	// 8 bytes
	case "long", "int64", "sint64":
		return btfSignedInt(name, 8), nil
	case "ulong", "uint64", "size_t":
		return btfUnsignedInt(name, 8), nil

	default:
		return nil, p.errorf("unsupported primitive type %q", name)
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
	return strings.Join(strings.Fields(raw), " ")
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
	p.Consume(']') // advance past ']', always succeeds since ReadUntil found it
	n, err := strconv.ParseUint(sizeLiteral, 10, 32)
	if err != nil {
		return 0, p.errorf("invalid array size %q", sizeLiteral)
	}
	if n == 0 {
		return 0, p.errorf("array size must be greater than 0")
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
