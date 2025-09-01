// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
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

func addPaddingOnNestedPtr(ty ebtf.Type, path []string) []string {
	if t, ok := ty.(*ebtf.Pointer); ok {
		updatedPath := append([]string{""}, path...)
		return addPaddingOnNestedPtr(t.Target, updatedPath)
	}
	return path
}

func hasCurrentTaskSource(arg *v1alpha1.KProbeArg) bool {
	return arg.Source == "current_task"
}

func resolveBTFArg(hook string, arg v1alpha1.KProbeArg, tp bool) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	btfArg := [api.MaxBTFArgDepth]api.ConfigBTFArg{}

	// tracepoints have extra first internal argument, so we need to adjust the index
	index := int(arg.Index)
	if tp {
		index++
	}

	var ty ebtf.Type

	// Getting argument data based on the source attribute, so far it's either:
	// - current task object
	// - real argument value
	if hasCurrentTaskSource(&arg) {
		st, err := btf.FindBTFStruct("task_struct")
		if err != nil && !errors.Is(err, ebtf.ErrMultipleMatches) {
			return nil, btfArg, err
		}
		ty = ebtf.Type(st)
	} else {
		param, err := btf.FindBTFFuncParamFromHook(hook, index)
		if err != nil {
			return nil, btfArg, err
		}

		ty = param.Type
		if ptr, isPointer := param.Type.(*ebtf.Pointer); isPointer {
			ty = ptr.Target
		}
	}

	pathBase := strings.Split(arg.Resolve, ".")
	path := addPaddingOnNestedPtr(ty, pathBase)
	if len(path) > api.MaxBTFArgDepth {
		return nil, btfArg, fmt.Errorf("unable to resolve %q. The maximum depth allowed is %d", arg.Resolve, api.MaxBTFArgDepth)
	}

	lastBTFType, err := resolveBTFPath(&btfArg, btf.ResolveNestedTypes(ty), path)
	return lastBTFType, btfArg, err
}

func resolveBTFPath(btfArg *[api.MaxBTFArgDepth]api.ConfigBTFArg, rootType ebtf.Type, path []string) (*ebtf.Type, error) {
	return btf.ResolveBTFPath(btfArg, rootType, path, 0)
}

func findTypeFromBTFType(arg v1alpha1.KProbeArg, btfType *ebtf.Type) int {
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
