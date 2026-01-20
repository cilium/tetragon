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
	"github.com/cilium/tetragon/pkg/btf"
	conf "github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/selectors"
)

// Takes arg.Resolve as input and return the path in []string
// Input   : my.super.field[123].my.sub.field
// Output  : []string{"my", "super", "field", "[123]", "my", "sub", "field"}
func formatBTFPath(resolvePath string) ([]string, error) {
	var path []string
	var buffer strings.Builder
	inBracket := false
	invalidFormat := false

	for i, r := range resolvePath {
		switch r {
		case '.':
			if inBracket || i > 0 && resolvePath[i-1] == '.' {
				invalidFormat = true
				break
			}
			if buffer.Len() > 0 {
				path = append(path, buffer.String())
				buffer.Reset()
			}
		case '[':
			if inBracket || i > 0 && resolvePath[i-1] == '.' {
				invalidFormat = true
				break
			}
			if buffer.Len() > 0 {
				path = append(path, buffer.String())
				buffer.Reset()
			}
			inBracket = true
			buffer.WriteRune(r)
		case ']':
			if !inBracket || i > 0 && resolvePath[i-1] == '[' {
				invalidFormat = true
				break
			}
			buffer.WriteRune(r)
			inBracket = false
			path = append(path, buffer.String())
			buffer.Reset()
		default:
			buffer.WriteRune(r)
		}
	}
	if invalidFormat || inBracket {
		return []string{}, fmt.Errorf("invalid format for resolve path: %q", resolvePath)
	}
	if buffer.Len() > 0 {
		path = append(path, buffer.String())
	}
	return path, nil
}

func addPaddingOnNestedPtr(ty ebtf.Type, path []string) []string {
	if t, ok := ty.(*ebtf.Pointer); ok {
		updatedPath := append([]string{"[0]"}, path...)
		return addPaddingOnNestedPtr(t.Target, updatedPath)
	}
	return path
}

func hasCurrentTaskSource(arg *v1alpha1.KProbeArg) bool {
	return arg.Source == "current_task"
}

func hasPtRegsSource(arg *v1alpha1.KProbeArg) bool {
	return arg.Source == "pt_regs"
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

	lastBTFType, err := resolveBTFPath(&btfArg, btf.ResolveNestedTypes(ty), path)
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
	} else {
		param, err := btf.FindBTFFuncParamFromHook(hook, index)
		if err != nil {
			return nil, [api.MaxBTFArgDepth]api.ConfigBTFArg{}, err
		}

		ty = param.Type
		if ptr, isPointer := param.Type.(*ebtf.Pointer); isPointer {
			ty = ptr.Target
		}
	}
	return resolveBTFType(arg, ty)
}

func resolveBTFPath(btfArg *[api.MaxBTFArgDepth]api.ConfigBTFArg, rootType ebtf.Type, path []string) (*ebtf.Type, error) {
	return btf.ResolveBTFPath(btfArg, rootType, path, 0)
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
