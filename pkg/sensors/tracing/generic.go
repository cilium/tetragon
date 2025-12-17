// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"strings"

	ebtf "github.com/cilium/ebpf/btf"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/btf"
	conf "github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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
