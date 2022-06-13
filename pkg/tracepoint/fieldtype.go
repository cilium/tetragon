// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracepoint

import (
	"fmt"
	"strconv"
	"strings"
)

type IntTyBase int

const (
	IntTyChar IntTyBase = iota
	IntTyShort
	IntTyInt
	IntTyLong
	IntTyLongLong
	IntTyInt8
	IntTyInt16
	IntTyInt32
	IntTyInt64
)

// integer type
type IntTy struct {
	Base     IntTyBase
	Unsigned bool
}

type BoolTy struct{}

// pid_t type
type PidTy struct{}

// pid_t type
type SizeTy struct{}

// void type
type VoidTy struct{}

// dma_addr_t
type DmaAddrTy struct{}

type PointerTy struct {
	Ty    interface{}
	Const bool
}

type ArrayTy struct {
	Ty   interface{}
	Size uint
}

type Field struct {
	Name string
	Type interface{}
}

type ParseError struct {
	r string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("failed to parse field: %s", e.r)
}

func parseTy(tyFields []string) (interface{}, error) {

	fidx := 0
	nfields := len(tyFields)
	isConst := false
	nextField := func() string {
		ret := tyFields[fidx]
		fidx++
		return ret
	}
	peekField := func() string {
		return tyFields[fidx]
	}
	lastField := func() bool {
		return fidx == nfields
	}

	if peekField() == "const" {
		isConst = true
		nextField()
	}

	ty := nextField()
	unsigned := false
	if ty == "unsigned" {
		// type just contains unsigned
		if lastField() {
			return IntTy{
				Base:     IntTyInt,
				Unsigned: true,
			}, nil
		}
		// unsigned is a qualifier
		unsigned = true
		ty = nextField()
	}

	var retTy interface{}
	switch {
	case ty == "char":
		retTy = IntTy{Base: IntTyChar, Unsigned: unsigned}
	case ty == "short":
		retTy = IntTy{Base: IntTyShort, Unsigned: unsigned}
	case ty == "int":
		retTy = IntTy{Base: IntTyInt, Unsigned: unsigned}
	case ty == "long":
		if !lastField() && peekField() == "long" {
			retTy = IntTy{Base: IntTyLongLong, Unsigned: unsigned}
			nextField()
		} else {
			retTy = IntTy{Base: IntTyLong, Unsigned: unsigned}
		}
	case unsigned == true:
		// we are doing something wrong if we hit this because we are ignoring the unsigned qualifier
		return nil, &ParseError{r: "unexpected unsigned"}
	case ty == "u8":
		retTy = IntTy{Base: IntTyInt8, Unsigned: true}
	case ty == "u16":
		retTy = IntTy{Base: IntTyInt16, Unsigned: true}
	case ty == "u32":
		retTy = IntTy{Base: IntTyInt32, Unsigned: true}
	case ty == "u64":
		retTy = IntTy{Base: IntTyInt64, Unsigned: true}
	case ty == "bool":
		retTy = BoolTy{}
	case ty == "pid_t":
		retTy = PidTy{}
	case ty == "size_t":
		retTy = SizeTy{}
	case ty == "void":
		retTy = VoidTy{}
	case ty == "dma_addr_t":
		retTy = DmaAddrTy{}
	default:
		return nil, &ParseError{r: fmt.Sprintf("unknown type:%s", ty)}
	}

	if lastField() {
		return retTy, nil
	}

	// Linux 5.16 started placing attributes in tracepoint format definitions
	// Let's just ignore them here for now
	if strings.HasPrefix(peekField(), "__attribute__") {
		nextField()
	}

	rest := nextField()
	if rest == "*" {
		retTy = PointerTy{Ty: retTy, Const: isConst}
	} else {
		return nil, &ParseError{r: "parsing failed"}
	}

	if !lastField() {
		return nil, &ParseError{r: "did not process all fields"}
	}
	return retTy, nil
}

func parseField(s string) (*Field, error) {

	fields := strings.Fields(s)
	nfields := len(fields)
	if nfields < 2 {
		return nil, &ParseError{r: "expecting at least two fields"}
	}

	tyFields := fields[0 : nfields-1]
	retTy, err := parseTy(tyFields)
	if err != nil {
		return nil, err
	}

	name := fields[nfields-1]
	if bOpen := strings.Index(name, "["); bOpen != -1 {
		var size uint64
		if !strings.HasSuffix(name, "]") {
			return nil, &ParseError{r: "could not parse array structure"}
		}
		substrings := strings.Split(name, "[")
		size_s := strings.TrimSuffix(substrings[1], "]")
		size, err = strconv.ParseUint(size_s, 10, 32)
		if err != nil {
			return nil, &ParseError{r: fmt.Sprintf("failed to parse size: %s", err)}
		}
		retTy = ArrayTy{
			Ty:   retTy,
			Size: uint(size),
		}
		name = substrings[0]
	}

	return &Field{
		Name: name,
		Type: retTy,
	}, nil
}

// NBytes retruns the number of bytes of an integer type
func (ty *IntTy) NBytes() (int, error) {
	var ret int
	switch ty.Base {
	case IntTyChar:
		ret = 1
	case IntTyShort:
		ret = 2
	case IntTyInt:
		ret = 4
	case IntTyLong:
		ret = 8
	case IntTyLongLong:
		ret = 8
	case IntTyInt8:
		ret = 1
	case IntTyInt16:
		ret = 2
	case IntTyInt32:
		ret = 4
	case IntTyInt64:
		ret = 8
	default:
		return ret, fmt.Errorf("unknown base: %d", ty.Base)
	}

	return ret, nil
}

// NBytes returns the number of bytes if an array type
// TODO: expand for types other than Int as needed
func (ty *ArrayTy) NBytes() (int, error) {
	switch x := ty.Ty.(type) {
	case IntTy:
		intBytes, err := x.NBytes()
		if err != nil {
			return 0, err
		}
		return intBytes * int(ty.Size), nil
	default:
		return 0, fmt.Errorf("NBytes: unknown type: %T", ty)
	}
}
