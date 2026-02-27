// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package btf

import (
	"fmt"
	"math"
	"os"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

var (
	btfFile string
)

func btfFileExists(file string) error {
	_, err := os.Stat(file)
	return err
}

func observerFindBTF(lib, btf string) (string, error) {
	if btf == "" {
		// Alternative to auto-discovery and/or command line argument we
		// can also set via environment variable.
		tetragonBTFEnv := os.Getenv("TETRAGON_BTF")
		if tetragonBTFEnv != "" {
			if _, err := os.Stat(tetragonBTFEnv); err != nil {
				return btf, err
			}
			return tetragonBTFEnv, nil
		}

		_, kernelVersion, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
		if err != nil {
			return btf, err
		}

		// Preference of BTF files, first search for kernel exposed BTF, then
		// check for vmlinux- hubble metadata, and finally if all those are missing
		// search the lib directory for a btf file.
		if _, err := os.Stat(defaults.DefaultBTFFile); err == nil {
			logger.GetLogger().Info("BTF discovery: default kernel btf file found", "btf-file", defaults.DefaultBTFFile)
			return defaults.DefaultBTFFile, nil
		}
		logger.GetLogger().Info("BTF discovery: default kernel btf file does not exist", "btf-file", defaults.DefaultBTFFile)

		runFile := path.Join(lib, "metadata", "vmlinux-"+kernelVersion)
		if _, err := os.Stat(runFile); err == nil {
			logger.GetLogger().Info("BTF discovery: candidate btf file found", "btf-file", runFile)
			return runFile, nil
		}
		logger.GetLogger().Info("BTF discovery: candidate btf file does not exist", "btf-file", runFile)

		runFile = path.Join(lib, "btf")
		if _, err := os.Stat(runFile); err == nil {
			logger.GetLogger().Info("BTF discovery: candidate btf file found", "btf-file", runFile)
			return runFile, nil
		}
		logger.GetLogger().Info("BTF discovery: candidate btf file does not exist", "btf-file", runFile)

		return btf, fmt.Errorf("kernel version %q BTF search failed kernel is not included in supported list. Please check Tetragon requirements documentation, then use --btf option to specify BTF path and/or '--kernel' to specify kernel version", kernelVersion)
	}
	if err := btfFileExists(btf); err != nil {
		return btf, fmt.Errorf("user specified BTF does not exist: %w", err)
	}
	logger.GetLogger().Info("BTF file: user specified btf file found", "btf-file", btf)
	return btf, nil
}

type Spec = btf.Spec

func NewBTF() (*btf.Spec, error) {
	return btf.LoadSpec(btfFile)
}

func InitCachedBTF(lib, btf string) error {
	var err error

	// Find BTF metdaata and populate btf opaqu object
	btfFile, err = observerFindBTF(lib, btf)
	if err != nil {
		return fmt.Errorf("tetragon, aborting kernel autodiscovery failed: %w", err)
	}
	return err
}

func GetCachedBTFFile() string {
	return btfFile
}

func FindBTFStruct(name string) (*btf.Struct, error) {
	var ty *btf.Struct

	spec, err := NewBTF()
	if err != nil {
		return nil, err
	}

	err = firstTypeByName(spec, name, &ty)
	return ty, err
}

// firstStructTypeByName mimics spec.TypeByName(), but returns first match found.
func firstTypeByName(spec *btf.Spec, name string, typ any) error {
	typeInterface := reflect.TypeFor[btf.Type]()

	// typ may be **T or *Type
	typValue := reflect.ValueOf(typ)
	if typValue.Kind() != reflect.Ptr {
		return fmt.Errorf("%T is not a pointer", typ)
	}

	typPtr := typValue.Elem()
	if !typPtr.CanSet() {
		return fmt.Errorf("%T cannot be set", typ)
	}

	wanted := typPtr.Type()
	if wanted == typeInterface {
		// This is *Type. Unwrap the value's type.
		wanted = typPtr.Elem().Type()
	}

	if !wanted.AssignableTo(typeInterface) {
		return fmt.Errorf("%T does not satisfy Type interface", typ)
	}

	types, err := spec.AnyTypesByName(name)
	if err != nil {
		return err
	}

	for _, typ := range types {
		if reflect.TypeOf(typ) != wanted {
			continue
		}
		typPtr.Set(reflect.ValueOf(typ))
		return nil
	}
	return btf.ErrNotFound
}

func FindBTFFuncParamFromHook(hook string, argIndex int) (*btf.FuncParam, error) {
	spec, err := NewBTF()
	if err != nil {
		return nil, err
	}
	return findBTFFuncParamFromHookWithSpec(spec, hook, argIndex)
}

func findBTFFuncParamFromHookWithSpec(spec *btf.Spec, hook string, argIndex int) (*btf.FuncParam, error) {
	var hookFn *btf.Func

	if err := spec.TypeByName(hook, &hookFn); err != nil {
		if strings.HasPrefix(hook, "bpf_lsm_") {
			return nil, fmt.Errorf("failed to find BTF type for hook %q: %w."+
				"Please check if the hook exists or if your kernel supports BTF for lsm hooks."+
				"As an alternative, consider switching to kprobes. ", hook, err)
		}
		return nil, fmt.Errorf("failed to find BTF type for hook %q: %w", hook, err)
	}

	btfHookProto, isBTFFuncProto := hookFn.Type.(*btf.FuncProto)
	if !isBTFFuncProto {
		return nil, fmt.Errorf("hook %q has no BTF type FuncProto", hook)
	}
	paramLen := len(btfHookProto.Params)
	if argIndex > paramLen-1 {
		parameter := "parameter"
		if paramLen > 1 {
			parameter += "s"
		}
		return nil, fmt.Errorf("index %d is out of range. The hook only have %d %q", argIndex, paramLen, parameter)
	}
	return &btfHookProto.Params[argIndex], nil
}

func ResolveNestedTypes(ty btf.Type) btf.Type {
	switch t := ty.(type) {
	case *btf.Restrict:
		return ResolveNestedTypes(t.Type)
	case *btf.Volatile:
		return ResolveNestedTypes(t.Type)
	case *btf.Const:
		return ResolveNestedTypes(t.Type)
	case *btf.Typedef:
		return ResolveNestedTypes(t.Type)
	}
	return ty
}

func parseArrayIdxStr(s string) (uint32, error) {
	re := regexp.MustCompile(`^\[(\d+)\]$`)

	matches := re.FindStringSubmatch(s)
	if len(matches) < 2 {
		return 0, fmt.Errorf("invalid format %q (must be: \"[value]\")", s)
	}

	n, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid value %q: %w", matches[1], err)
	}

	if n < 0 || n > math.MaxUint32 {
		return 0, fmt.Errorf("value %d out of range for uint32", n)
	}

	return uint32(n), nil
}

func getSizeofType(t btf.Type) uint32 {
	ret, _ := btf.Sizeof(t)
	return uint32(ret)
}

func shouldContinueResolving(currentType btf.Type, argTypeIsPointer bool) bool {
	currentType = ResolveNestedTypes(currentType)
	_, currentTypeIsPointer := currentType.(*btf.Pointer)
	if argTypeIsPointer {
		if currentTypeIsPointer {
			var isNestedPointer bool
			targetType := ResolveNestedTypes(currentType.(*btf.Pointer).Target)
			_, isNestedPointer = targetType.(*btf.Pointer)
			if isNestedPointer {
				return true
			}
		}
	} else {
		if currentTypeIsPointer {
			return true
		}
	}
	return false
}

func ResolveBTFPath(
	btfArgs *[api.MaxBTFArgDepth]api.ConfigBTFArg,
	currentType btf.Type,
	path []string,
	argTypeIsPointer bool,
) error {
	var err error
	pathLen := len(path)
	pathIdx := 0
	configIdx := 0
	currentOffset := uint32(0)

	for pathIdx < pathLen || shouldContinueResolving(currentType, argTypeIsPointer) {
		currentType = ResolveNestedTypes(currentType)

		if pathIdx < pathLen {
			var idx uint32
			idx, err = parseArrayIdxStr(path[pathIdx])
			_, isArray := currentType.(*btf.Array)
			_, isPointer := currentType.(*btf.Pointer)
			isNestedPointer := false
			if isPointer {
				targetType := ResolveNestedTypes(currentType.(*btf.Pointer).Target)
				_, isNestedPointer = targetType.(*btf.Pointer)
			}

			if err == nil && !isArray && !isNestedPointer {
				// handle dynamic array / pointer decay
				currentOffset += getSizeofType(currentType) * idx
				pathIdx++
				continue
			}
		}

		switch t := currentType.(type) {
		case *btf.Pointer:
			if configIdx >= api.MaxBTFArgDepth {
				return fmt.Errorf("The maximum depth allowed is %d", api.MaxBTFArgDepth)
			}
			btfArgs[configIdx].IsPointer = uint16(1)
			btfArgs[configIdx].IsInitialized = uint16(1)
			btfArgs[configIdx].Offset = currentOffset
			configIdx++
			currentOffset = 0
			currentType = t.Target
		default:
			var offset uint32
			offset, currentType, err = processCompoundType(currentType, path[pathIdx])
			if err != nil {
				return err
			}
			currentOffset += offset

			pathIdx++
		}
	}

	if configIdx >= api.MaxBTFArgDepth {
		return fmt.Errorf("The maximum depth allowed is %d", api.MaxBTFArgDepth)
	}

	btfArgs[configIdx].IsInitialized = uint16(1)
	btfArgs[configIdx].Offset = currentOffset
	_, currentTypeIsPointer := currentType.(*btf.Pointer)

	if argTypeIsPointer && !currentTypeIsPointer {
		btfArgs[configIdx].IsPointer = uint16(0)
	} else {
		btfArgs[configIdx].IsPointer = uint16(1)
	}

	return nil
}

func processCompoundType(currentType btf.Type, pathElement string) (uint32, btf.Type, error) {
	switch t := currentType.(type) {
	case *btf.Struct:
		return processMembers(pathElement, t.Members)
	case *btf.Union:
		return processMembers(pathElement, t.Members)
	case *btf.Array:
		idx, err := parseArrayIdxStr(pathElement)
		if err != nil {
			return 0, nil, fmt.Errorf("fail parsing array index : %w", err)
		}
		if idx >= t.Nelems {
			return 0, nil, fmt.Errorf("array index out of bound. Nelems=%d, got=%d", t.Nelems, idx)
		}

		elementType := ResolveNestedTypes(t.Type)
		return getSizeofType(elementType) * idx, elementType, nil
	default:
		return 0, nil, fmt.Errorf("unexpected type : %q has type %q", pathElement, reflect.TypeOf(currentType))
	}
}

func processMembers(
	pathElement string,
	members []btf.Member,
) (uint32, btf.Type, error) {
	for _, member := range members {
		if len(member.Name) == 0 { // anonymous struct/union
			var offset uint32
			var ty btf.Type
			var err error
			switch t := member.Type.(type) {
			case *btf.Struct:
				offset, ty, err = processMembers(pathElement, t.Members)
			case *btf.Union:
				offset, ty, err = processMembers(pathElement, t.Members)
			default:
				//FIXME: this error can be hidden
				return 0, nil, fmt.Errorf("unexpected anonymous member type %q", reflect.TypeOf(member.Type))
			}
			if err == nil {
				return offset, ty, nil
			}
		} else if member.Name == pathElement {
			return member.Offset.Bytes(), member.Type, nil
		}
	}

	return 0, nil, fmt.Errorf(
		"attribute %q not found in structure",
		pathElement)

}
