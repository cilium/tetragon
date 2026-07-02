// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	ebtf "github.com/cilium/ebpf/btf"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/asm"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	conf "github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/selectors"
)

// formatBTFPath parses resolvePath into a token slice for the BTF resolver.
//
// A bare cast may only open the path, where its operand is the whole trailing
// chain. Anywhere else it must use the grouped form ((type*)target), which
// carries its own operand bounds.
//
// Example:
//
//	input:  "my.super.((struct my_struct *)((char*)field)[123]).my.sub.field"
//	output: []string{"my", "super", "field", "(char*)", "[123]", "(struct my_struct *)", "my", "sub", "field"}
func formatBTFPath(resolvePath string) ([]string, error) {
	var pathToFind []string
	var pendingCast string // deferred cast token from a leading bare or paren-target cast

	for i, step := range strings.Split(resolvePath, ".") {
		if step == "" {
			return nil, fmt.Errorf("invalid resolve path %q: empty segment", resolvePath)
		}
		if i > 0 && step[0] == '[' {
			return nil, fmt.Errorf("invalid resolve path %q: dot before '['", resolvePath)
		}

		var (
			tokens     []string
			newPending string
			err        error
		)
		switch step[0] {
		case '(':
			tokens, newPending, err = parseCastSegment(step)
		case '[':
			tokens, err = parseArrays(step)
		default:
			tokens, err = parseIdentAndArrays(step)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid resolve path %q: %w", resolvePath, err)
		}
		pathToFind = append(pathToFind, tokens...)
		if newPending != "" {
			// Deferring a cast across a dot only reads unambiguously when the
			// cast opens the path: there, its operand is everything that
			// follows. Mid-path, the grouped form must say where it ends.
			if i > 0 {
				return nil, fmt.Errorf("invalid resolve path %q: a cast that does not open the path must be grouped, e.g. ((type*)target)", resolvePath)
			}
			pendingCast = newPending
		}
	}

	if pendingCast != "" {
		pathToFind = append(pathToFind, pendingCast)
	}
	return pathToFind, nil
}

// matchingParenDepth returns the index of the ')' that closes the '(' at s[0].
// Returns -1 if not found.
func matchingParenDepth(s string) int {
	depth := 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseArrays parses one or more "[N]" tokens from s, e.g. "[0][1]" → ["[0]", "[1]"].
// N must be a decimal uint32.
func parseArrays(s string) ([]string, error) {
	var tokens []string
	for len(s) > 0 {
		if s[0] != '[' {
			return nil, fmt.Errorf("unexpected character %q, expected '['", s[0])
		}
		inner, rest, found := strings.Cut(s[1:], "]")
		if !found {
			return nil, fmt.Errorf("unclosed bracket: %q", s)
		}
		if inner == "" {
			return nil, errors.New("empty bracket")
		}
		if _, err := strconv.ParseUint(inner, 10, 32); err != nil {
			return nil, fmt.Errorf("invalid bracket content %q: must be a decimal uint32", inner)
		}
		tokens = append(tokens, "["+inner+"]")
		s = rest
	}
	return tokens, nil
}

// parseIdentAndArrays parses an identifier followed by optional "[N]" arrays,
// e.g. "field[0][1]" → ["field", "[0]", "[1]"].
func parseIdentAndArrays(s string) ([]string, error) {
	ident, arraySuffix, hasArraySuffix := strings.Cut(s, "[")

	if strings.ContainsAny(ident, "()[]]") {
		return nil, fmt.Errorf("invalid identifier: %q", ident)
	}

	if !hasArraySuffix {
		return []string{ident}, nil
	}

	// Re-prepend the '[' that Cut consumed before delegating to parseArrays.
	arrays, err := parseArrays("[" + arraySuffix)
	if err != nil {
		return nil, err
	}
	return slices.Concat([]string{ident}, arrays), nil
}

func parseCastSegment(s string) (tokens []string, pendingCast string, err error) {
	if s[0] != '(' {
		tokens, err = parseIdentAndArrays(s)
		return
	}

	var grouped []string
	didStrip := false

	// Peel grouped casts: ((T*)p)[n] → strip outer parens, accumulate trailing
	// arrays innermost-first. Each level prepends its arrays before the outer ones.
	for {
		idx := strings.IndexAny(s[1:], "()")
		if idx < 0 {
			return nil, "", fmt.Errorf("unclosed cast: %q", s)
		}
		castEnd := idx + 1
		if s[castEnd] != '(' {
			break
		}
		outerEnd := matchingParenDepth(s)
		if outerEnd < 0 {
			return nil, "", errors.New("unclosed outer parenthesis")
		}
		var arrays []string
		if arrays, err = parseArrays(s[outerEnd+1:]); err != nil {
			return nil, "", err
		}
		grouped = append(arrays, grouped...)
		s, didStrip = s[1:outerEnd], true
	}

	idx := strings.IndexAny(s[1:], "()")
	castEnd := idx + 1
	castType := strings.TrimSpace(s[1:castEnd])
	if len(castType) == 0 {
		return nil, "", fmt.Errorf("empty cast type: %q", s[:castEnd+1])
	}
	castToken := "(" + castType + ")"

	rest := s[castEnd+1:]
	if len(rest) == 0 {
		return nil, "", errors.New("cast with no target: expected (type*)target or (type*)(target)")
	}

	inner, postSuffix := rest, ""
	if rest[0] == '(' {
		targetEnd := matchingParenDepth(rest)
		if targetEnd < 0 {
			return nil, "", errors.New("unclosed target parenthesis")
		}
		inner, postSuffix = rest[1:targetEnd], rest[targetEnd+1:]
		if inner == "" {
			return nil, "", errors.New("empty cast target")
		}
	}

	var innerTokens []string
	var innerPending string
	if innerTokens, innerPending, err = parseCastSegment(inner); err != nil {
		return nil, "", err
	}
	if innerPending != "" {
		innerTokens = append(innerTokens, innerPending)
	}

	var postArrays []string
	if postArrays, err = parseArrays(postSuffix); err != nil {
		return nil, "", err
	}
	if didStrip {
		return slices.Concat(innerTokens, postArrays, []string{castToken}, grouped), "", nil
	}
	return slices.Concat(innerTokens, postArrays), castToken, nil
}

// First argument is added to enforce the method to be called on a pointer type
func isPointerToIndexedArray(_ *ebtf.Pointer, firstResolvePath string) bool {
	var idx int
	n, _ := fmt.Sscanf(firstResolvePath, `[%d]`, &idx)
	return n == 1
}

func addPaddingOnNestedPtr(ty ebtf.Type, path []string) []string {
	if t, ok := ty.(*ebtf.Pointer); ok {
		// If we are going to dereference the pointer by index,
		// there is no need to force-dereference it.
		if !isPointerToIndexedArray(t, path[0]) {
			updatedPath := append([]string{"[0]"}, path...)
			return addPaddingOnNestedPtr(t.Target, updatedPath)
		}
	}
	return path
}

func hasCurrentTaskSource(arg *v1alpha1.KProbeArg) bool {
	return arg.Source == "current_task"
}

func hasPtRegsSource(arg *v1alpha1.KProbeArg) bool {
	return arg.Source == "pt_regs"
}

func resolvePtRegsArg(resolve string) (api.ConfigRegArg, [api.MaxBTFArgDepth]api.ConfigBTFArg, bool, error) {
	var (
		regArg api.ConfigRegArg
		btfArg [api.MaxBTFArgDepth]api.ConfigBTFArg
	)

	path, err := formatBTFPath(resolve)
	if err != nil {
		return regArg, btfArg, false, err
	}
	if len(path) == 0 {
		return regArg, btfArg, false, errors.New("empty register argument resolve path")
	}

	var ok bool
	regArg.Offset, regArg.Size, ok = asm.RegOffsetSize(path[0])
	if !ok {
		return regArg, btfArg, false, fmt.Errorf("failed to retrieve register argument %q", resolve)
	}

	path = path[1:]
	if len(path) == 0 {
		return regArg, btfArg, false, nil
	}
	if !bpf.HasProgramLargeSize() {
		return regArg, btfArg, false, errors.New("resolve flag can't be used for your kernel version. Please update to version 5.4 or higher or disable Resolve flag")
	}
	if len(path) > api.MaxBTFArgDepth {
		return regArg, btfArg, false, fmt.Errorf("unable to resolve %q. The maximum depth allowed is %d", resolve, api.MaxBTFArgDepth)
	}

	_, err = btf.ResolveBTFPath(&btfArg, &ebtf.Void{}, path, nil)
	if err != nil {
		return regArg, btfArg, false, fmt.Errorf("failed to resolve pt_regs path %q: %w", resolve, err)
	}
	return regArg, btfArg, true, nil
}

func resolveBTFType(arg *v1alpha1.KProbeArg, ty ebtf.Type) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	btfArg := [api.MaxBTFArgDepth]api.ConfigBTFArg{}
	pathBase, err := formatBTFPath(arg.Resolve)
	if err != nil {
		return nil, btfArg, err
	}
	path := addPaddingOnNestedPtr(ty, pathBase)
	if len(path) > api.MaxBTFArgDepth {
		return nil, btfArg, fmt.Errorf("unable to resolve %q. The maximum depth allowed is %d", arg.Resolve, api.MaxBTFArgDepth)
	}

	lastBTFType, err := btf.ResolveBTFPath(&btfArg, btf.ResolveNestedTypes(ty), path, nil)
	return lastBTFType, btfArg, err
}

func resolveUserBTFArg(arg *v1alpha1.KProbeArg, btfPath string) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	spec, err := ebtf.LoadSpec(btfPath)
	if err != nil {
		return nil, [api.MaxBTFArgDepth]api.ConfigBTFArg{}, err
	}

	var st *ebtf.Struct
	err = spec.TypeByName(arg.BTFType, &st)
	if err != nil {
		return nil, [api.MaxBTFArgDepth]api.ConfigBTFArg{}, err
	}
	ty := ebtf.Type(st)
	return resolveBTFType(arg, ty)
}

func findBTFTypeStruct(hook string, arg *v1alpha1.KProbeArg) (*ebtf.Struct, error) {
	if arg.BTFTypeModule != "" {
		st, err := btf.FindBTFStructInModule(arg.BTFType, arg.BTFTypeModule)
		if err != nil {
			return nil, fmt.Errorf("failed to find BTF type %q in module %q: %w", arg.BTFType, arg.BTFTypeModule, err)
		}
		return st, nil
	}

	st, err := btf.FindBTFStruct(arg.BTFType)
	if err == nil || !errors.Is(err, ebtf.ErrNotFound) {
		return st, err
	}

	st, module, moduleErr := btf.FindBTFStructInHookModule(hook, arg.BTFType)
	if moduleErr == nil {
		return st, nil
	}
	if module == "" {
		return nil, err
	}
	return nil, fmt.Errorf("failed to find BTF type %q in kernel BTF or module %q: %w", arg.BTFType, module, errors.Join(err, moduleErr))
}

func resolveBTFArg(hook string, arg *v1alpha1.KProbeArg, tp bool) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	// tracepoints have extra first internal argument, so we need to adjust the index
	index := int(arg.Index)
	if tp {
		index++
	}

	var ty ebtf.Type

	// Getting argument data based on the source attribute, so far it's either:
	// - current task object
	// - real argument value
	if hasCurrentTaskSource(arg) {
		st, err := btf.FindBTFStruct("task_struct")
		if err != nil {
			return nil, [api.MaxBTFArgDepth]api.ConfigBTFArg{}, err
		}
		ty = ebtf.Type(st)
	} else if arg.BTFType != "" {
		st, err := findBTFTypeStruct(hook, arg)
		if err != nil {
			return nil, [api.MaxBTFArgDepth]api.ConfigBTFArg{}, err
		}
		ty = ebtf.Type(st)
	} else {
		param, err := btf.FindBTFFuncParamFromHook(hook, index)
		if err != nil {
			return nil, [api.MaxBTFArgDepth]api.ConfigBTFArg{}, err
		}

		ty = param.Type
		if ptr, isPointer := param.Type.(*ebtf.Pointer); isPointer {
			if !isPointerToIndexedArray(ptr, arg.Resolve) {
				// If we are going to dereference the pointer by index,
				// there is no need to force-dereference it.
				ty = ptr.Target
			}
		}
	}
	return resolveBTFType(arg, ty)
}

func findTypeFromBTFType(arg *v1alpha1.KProbeArg, btfType *ebtf.Type) int {
	ty := generictypes.GenericTypeFromBTF(*btfType)
	if ty == generictypes.GenericInvalidType {
		return generictypes.GenericTypeFromString(arg.Type)
	}
	return ty
}

func pathArgWarning(index uint32, ty int, s []v1alpha1.KProbeSelector) {
	if !conf.EnableLargeProgs() && generictypes.PathType(ty) && selectors.HasFilter(s, index) {
		name, err := generictypes.GenericTypeToString(ty)
		if err != nil {
			name = "N/A"
		}
		logger.GetLogger().Warn(fmt.Sprintf("argument filter for '%s' (index %d) does not support the whole path retrieval",
			name, index))
	}
}

func appendMacrosSelectors(selectors []v1alpha1.KProbeSelector, macros map[string]v1alpha1.KProbeSelector) error {
	for i := range selectors {
		selector := &selectors[i]
		for _, macroName := range selector.Macros {
			if len(macros) == 0 {
				return fmt.Errorf("macro '%s' is used in selector, but no macros were defined in policy spec", macroName)
			}
			macro, ok := macros[macroName]
			if !ok {
				return fmt.Errorf("undefined macro '%s'", macroName)
			}
			if len(macro.Macros) > 0 {
				return errors.New("macro definition cannot use other macros")
			}
			if selector.Label == "" {
				selector.Label = macro.Label
			}

			var err error
			selector.MatchPIDs, err = useMacro(selector.MatchPIDs, macro.MatchPIDs)
			if err != nil {
				return err
			}

			selector.MatchArgs, err = useMacro(selector.MatchArgs, macro.MatchArgs)
			if err != nil {
				return err
			}

			selector.MatchData, err = useMacro(selector.MatchData, macro.MatchData)
			if err != nil {
				return err
			}

			selector.MatchActions, err = useMacro(selector.MatchActions, macro.MatchActions)
			if err != nil {
				return err
			}

			selector.MatchReturnArgs, err = useMacro(selector.MatchReturnArgs, macro.MatchReturnArgs)
			if err != nil {
				return err
			}

			selector.MatchReturnActions, err = useMacro(selector.MatchReturnActions, macro.MatchReturnActions)
			if err != nil {
				return err
			}

			selector.MatchBinaries, err = useMacro(selector.MatchBinaries, macro.MatchBinaries)
			if err != nil {
				return err
			}

			selector.MatchParentBinaries, err = useMacro(selector.MatchParentBinaries, macro.MatchParentBinaries)
			if err != nil {
				return err
			}

			selector.MatchNamespaces, err = useMacro(selector.MatchNamespaces, macro.MatchNamespaces)
			if err != nil {
				return err
			}

			selector.MatchNamespaceChanges, err = useMacro(selector.MatchNamespaceChanges, macro.MatchNamespaceChanges)
			if err != nil {
				return err
			}

			selector.MatchCapabilities, err = useMacro(selector.MatchCapabilities, macro.MatchCapabilities)
			if err != nil {
				return err
			}

			selector.MatchCapabilityChanges, err = useMacro(selector.MatchCapabilityChanges, macro.MatchCapabilityChanges)
			if err != nil {
				return err
			}

			selector.MatchUserCallers, err = useMacro(selector.MatchUserCallers, macro.MatchUserCallers)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func useMacro[T any](filters []T, macrosFilters []T) ([]T, error) {
	if len(filters) > 0 && len(macrosFilters) > 0 {
		return nil, fmt.Errorf("%T: field is defined in multiple macros and/or policy selectors", filters[0])
	}
	return append(filters, macrosFilters...), nil
}

type InstanceID int

func (i InstanceID) PinProg(name string) string {
	if i != 0 {
		return fmt.Sprintf("%s:%d", name, i)
	}
	return name
}

type DupInstance struct {
	dups map[string]InstanceID
}

func NewDupInstance() *DupInstance {
	return &DupInstance{make(map[string]InstanceID)}
}

func (d *DupInstance) GetID(name string) InstanceID {
	// Make sure duplicate symbols got non zero instance value
	instance, ok := d.dups[name]
	if ok {
		instance = instance + 1
	}
	d.dups[name] = instance
	return instance
}
