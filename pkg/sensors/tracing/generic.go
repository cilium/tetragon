// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
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

// Takes arg.Resolve as input and return the path in []string
// Input   : my.super.((char*)field)[123].my.sub.field
// Output  : []string{"my", "super", "field", "(char*)", "[123]", "my", "sub", "field"}
func formatBTFPath(resolvePath string) ([]string, error) {
	var path []string
	i := 0
	lastWasDot := false

	var parse func(stopAtCloseParen bool) error
	parse = func(stopAtCloseParen bool) error {
		for i < len(resolvePath) {
			tail := resolvePath[i:]

			switch {
			case stopAtCloseParen && tail[0] == ')':
				if len(path) == 0 {
					return errors.New("empty cast expression")
				}
				i++ // Consume the ')'
				return nil

			case strings.HasPrefix(tail, "(("):
				castEnd := strings.IndexByte(tail, ')')
				if castEnd <= 2 || strings.ContainsAny(tail[2:castEnd], "()") {
					return errors.New("invalid prefixed cast")
				}
				castToken := tail[1 : castEnd+1]

				i += castEnd + 1 // Move the cursor after the "((cast)"
				if err := parse(true); err != nil {
					return err
				}

				path = append(path, castToken)
				lastWasDot = false

			case tail[0] == '[':
				if lastWasDot {
					return errors.New("dot followed by '['")
				}
				end := strings.IndexByte(tail, ']')
				if end <= 1 || strings.ContainsAny(tail[1:end], ".[()") {
					return errors.New("invalid index token")
				}
				path = append(path, tail[:end+1])
				i += end + 1
				lastWasDot = false

			case tail[0] == '(':
				return errors.New("type casts must use ((cast)field)")
			case tail[0] == ')':
				return errors.New("mismatched closing parenthesis")

			case tail[0] == '.':
				if lastWasDot {
					return errors.New("consecutive dots")
				}
				lastWasDot = true
				i++

			default:
				end := strings.IndexAny(tail, ".[()]")
				var ident string
				if end == -1 {
					ident = tail
					i += len(tail)
				} else {
					ident = tail[:end]
					i += end
				}

				if ident == "" || strings.ContainsAny(ident, "])") {
					return errors.New("invalid or mismatched identifier")
				}
				if i < len(resolvePath) && resolvePath[i] == '(' {
					return errors.New("type casts must use ((cast)field)")
				}
				path = append(path, ident)
				lastWasDot = false
			}
		}

		if stopAtCloseParen {
			return errors.New("missing closing parenthesis")
		}
		return nil
	}

	if err := parse(false); err != nil {
		return nil, fmt.Errorf("invalid format for resolve path %q: %w", resolvePath, err)
	}

	return path, nil
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

func resolvePtRegsArg(resolve string, userBTFSpec *ebtf.Spec) (api.ConfigRegArg, [api.MaxBTFArgDepth]api.ConfigBTFArg, bool, error) {
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

	_, err = btf.ResolveBTFPath(&btfArg, &ebtf.Void{}, path, userBTFSpec)
	if err != nil {
		return regArg, btfArg, false, fmt.Errorf("failed to resolve pt_regs path %q: %w", resolve, err)
	}
	return regArg, btfArg, true, nil
}

func resolveBTFType(arg *v1alpha1.KProbeArg, ty ebtf.Type, spec *ebtf.Spec) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	btfArg := [api.MaxBTFArgDepth]api.ConfigBTFArg{}
	pathBase, err := formatBTFPath(arg.Resolve)
	if err != nil {
		return nil, btfArg, err
	}
	path := addPaddingOnNestedPtr(ty, pathBase)
	if len(path) > api.MaxBTFArgDepth {
		return nil, btfArg, fmt.Errorf("unable to resolve %q. The maximum depth allowed is %d", arg.Resolve, api.MaxBTFArgDepth)
	}

	lastBTFType, err := btf.ResolveBTFPath(&btfArg, btf.ResolveNestedTypes(ty), path, spec)
	return lastBTFType, btfArg, err
}

func resolveUserBTFArg(arg *v1alpha1.KProbeArg, userBTFSpec *ebtf.Spec) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	var st *ebtf.Struct
	err := userBTFSpec.TypeByName(arg.BTFType, &st)
	if err != nil {
		return nil, [api.MaxBTFArgDepth]api.ConfigBTFArg{}, err
	}
	ty := ebtf.Type(st)
	return resolveBTFType(arg, ty, userBTFSpec)
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

func resolveBTFArg(hook string, arg *v1alpha1.KProbeArg, tp bool, spec *ebtf.Spec) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
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
	return resolveBTFType(arg, ty, spec)
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
