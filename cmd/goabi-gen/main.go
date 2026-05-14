// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// goabi-gen resolves Go function signatures via go/types and emits a
// pre-computed ABI register-slot table for use by the uprobe sensor.
//
// Usage:
//
//	go run github.com/cilium/tetragon/cmd/goabi-gen
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/types"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// symbols lists the Go functions we need ABI slot info for.
// Add new entries here and re-run go generate.
var symbols = []string{
	"net/http.ServeContent",
	"net/http.ServeFile",
	"net/http.Get",
	"net/http.NewRequest",
	"path/filepath.Clean",
	"strings.ToUpper",
	"os.Open",
	"os.OpenFile",
	"os.ReadFile",
	"os.WriteFile",
	"text/template.(*Template).Parse",
	"html/template.(*Template).Parse",
	"github.com/cilium/tetragon/pkg/sensors/tracing/goabitest.ReportLenForABI",
}

var methodRe = regexp.MustCompile(`^(.+)\.\(\*(\w+)\)\.(\w+)$`)

type parsedSymbol struct {
	PkgPath    string
	TypeName   string
	MethodName string
	FuncName   string
}

func parseSymbol(sym string) parsedSymbol {
	if m := methodRe.FindStringSubmatch(sym); m != nil {
		return parsedSymbol{PkgPath: m[1], TypeName: m[2], MethodName: m[3]}
	}
	idx := strings.LastIndex(sym, ".")
	if idx < 0 {
		log.Fatalf("invalid symbol %q: no package separator", sym)
	}
	return parsedSymbol{PkgPath: sym[:idx], FuncName: sym[idx+1:]}
}

// intRegSlots computes integer register slots for a Go type per ABIInternal.
// See https://go.googlesource.com/go/+/refs/heads/master/src/cmd/compile/abi-internal.md
func intRegSlots(t types.Type) (int, error) {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		if u.Kind() == types.String {
			return 2, nil
		}
		if u.Info()&(types.IsFloat|types.IsComplex) != 0 {
			return 0, nil
		}
		return 1, nil
	case *types.Pointer:
		return 1, nil
	case *types.Slice:
		return 3, nil
	case *types.Interface:
		return 2, nil
	case *types.Struct:
		n := 0
		for field := range u.Fields() {
			m, err := intRegSlots(field.Type())
			if err != nil {
				return 0, fmt.Errorf("struct field %s: %w", field.Name(), err)
			}
			n += m
		}
		return n, nil
	case *types.Map, *types.Chan:
		return 1, nil
	case *types.Signature:
		return 1, nil
	case *types.Array:
		m, err := intRegSlots(u.Elem())
		if err != nil {
			return 0, fmt.Errorf("array element: %w", err)
		}
		return int(u.Len()) * m, nil
	}
	return 0, fmt.Errorf("unsupported type %s (underlying %T): refusing to guess slot count", t, t.Underlying())
}

func slotOffsets(sig *types.Signature) ([]int, error) {
	params := sig.Params()
	offsets := make([]int, params.Len())
	slot := 0
	for i := range params.Len() {
		offsets[i] = slot
		n, err := intRegSlots(params.At(i).Type())
		if err != nil {
			return nil, fmt.Errorf("param %d (%s): %w", i, params.At(i).Name(), err)
		}
		slot += n
	}
	return offsets, nil
}

func resolveFunc(pkg *packages.Package, ps parsedSymbol) *types.Func {
	scope := pkg.Types.Scope()

	if ps.FuncName != "" {
		obj := scope.Lookup(ps.FuncName)
		if obj == nil {
			return nil
		}
		fn, ok := obj.(*types.Func)
		if !ok {
			return nil
		}
		return fn
	}

	obj := scope.Lookup(ps.TypeName)
	if obj == nil {
		return nil
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		return nil
	}
	ptr := types.NewPointer(named)
	mset := types.NewMethodSet(ptr)
	sel := mset.Lookup(pkg.Types, ps.MethodName)
	if sel == nil {
		return nil
	}
	fn, ok := sel.Obj().(*types.Func)
	if !ok {
		return nil
	}
	return fn
}

func main() {
	pkgPaths := map[string]bool{}
	parsed := make([]parsedSymbol, len(symbols))
	for i, sym := range symbols {
		parsed[i] = parseSymbol(sym)
		pkgPaths[parsed[i].PkgPath] = true
	}

	paths := make([]string, 0, len(pkgPaths))
	for p := range pkgPaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	cfg := &packages.Config{Mode: packages.NeedTypes | packages.NeedName}
	pkgs, err := packages.Load(cfg, paths...)
	if err != nil {
		log.Fatalf("packages.Load: %v", err)
	}

	pkgMap := map[string]*packages.Package{}
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			log.Fatalf("package %s: %v", pkg.PkgPath, pkg.Errors)
		}
		pkgMap[pkg.PkgPath] = pkg
	}

	type entry struct {
		symbol  string
		offsets []int
	}
	var entries []entry

	for i, sym := range symbols {
		ps := parsed[i]
		pkg, ok := pkgMap[ps.PkgPath]
		if !ok {
			log.Fatalf("package %q not loaded", ps.PkgPath)
		}
		fn := resolveFunc(pkg, ps)
		if fn == nil {
			log.Fatalf("could not resolve %q", sym)
		}
		sig := fn.Type().(*types.Signature)

		recv := sig.Recv()
		var offsets []int
		if recv != nil {
			recvSlots, err := intRegSlots(recv.Type())
			if err != nil {
				log.Fatalf("%s: receiver: %v", sym, err)
			}
			paramOffsets, err := slotOffsets(sig)
			if err != nil {
				log.Fatalf("%s: %v", sym, err)
			}
			offsets = make([]int, 1+len(paramOffsets))
			offsets[0] = 0
			for j, o := range paramOffsets {
				offsets[j+1] = recvSlots + o
			}
		} else {
			var err error
			offsets, err = slotOffsets(sig)
			if err != nil {
				log.Fatalf("%s: %v", sym, err)
			}
		}

		entries = append(entries, entry{symbol: sym, offsets: offsets})
	}

	var buf bytes.Buffer
	buf.WriteString("// Code generated by goabi-gen; DO NOT EDIT.\n\n")
	buf.WriteString("// SPDX-License-Identifier: Apache-2.0\n")
	buf.WriteString("// Copyright Authors of Tetragon\n\n")
	buf.WriteString("package tracing\n\n")
	buf.WriteString("var goABIKnownFuncs = map[string][]int{\n")
	for _, e := range entries {
		strs := make([]string, len(e.offsets))
		for j, o := range e.offsets {
			strs[j] = strconv.Itoa(o)
		}
		fmt.Fprintf(&buf, "\t%q: {%s},\n", e.symbol, strings.Join(strs, ", "))
	}
	buf.WriteString("}\n")

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("gofmt: %v", err)
	}

	outPath := "pkg/sensors/tracing/goabi_slots_gen.go"
	if err := os.WriteFile(outPath, formatted, 0644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	fmt.Printf("wrote %s (%d entries)\n", outPath, len(entries))
}
