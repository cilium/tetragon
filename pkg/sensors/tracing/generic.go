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
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func addPaddingOnNestedPtr(ty ebtf.Type, path []string) []string {
	if t, ok := ty.(*ebtf.Pointer); ok {
		updatedPath := append([]string{""}, path...)
		return addPaddingOnNestedPtr(t.Target, updatedPath)
	}
	return path
}

func resolveBTFArg(hook string, arg v1alpha1.KProbeArg) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	btfArg := [api.MaxBTFArgDepth]api.ConfigBTFArg{}

	param, err := btf.FindBTFFuncParamFromHook(hook, int(arg.Index))
	if err != nil {
		return nil, btfArg, err
	}

	rootType := param.Type
	if rootTy, isPointer := param.Type.(*ebtf.Pointer); isPointer {
		rootType = rootTy.Target
	}

	pathBase := strings.Split(arg.Resolve, ".")
	path := addPaddingOnNestedPtr(rootType, pathBase)
	if len(path) > api.MaxBTFArgDepth {
		return nil, btfArg, fmt.Errorf("Unable to resolve %q. The maximum depth allowed is %d", arg.Resolve, api.MaxBTFArgDepth)
	}

	lastBTFType, err := resolveBTFPath(&btfArg, btf.ResolveNestedTypes(rootType), path)
	return lastBTFType, btfArg, err
}

func resolveBTFPath(btfArg *[api.MaxBTFArgDepth]api.ConfigBTFArg, rootType ebtf.Type, path []string) (*ebtf.Type, error) {
	return btf.ResolveBTFPath(btfArg, rootType, path, 0)
}

func findTypeFromBTFType(arg v1alpha1.KProbeArg, btfType *ebtf.Type) int {
	ty := gt.GenericTypeFromBTF(*btfType)
	if ty == gt.GenericInvalidType {
		return gt.GenericTypeFromString(arg.Type)
	}
	return ty
}
