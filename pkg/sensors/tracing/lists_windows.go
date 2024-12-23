// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"strings"

	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// isList checks if a value specifies a list, and if so it returns it (or nil if list does not exist)
func isList(val string, lists []v1alpha1.ListSpec) (bool, *v1alpha1.ListSpec) {
	name, found := strings.CutPrefix(val, "list:")
	if !found {
		return false, nil
	}
	for idx := range lists {
		list := &lists[idx]
		if list.Name == name {
			return true, list
		}
	}
	return true, nil

}

const (
	ListTypeInvalid           = -1
	ListTypeNone              = 0
	ListTypeSyscalls          = 1
	ListTypeGeneratedSyscalls = 2
	ListTypeGeneratedFtrace   = 3

	Is32Bit = 0x80000000
)

var listTypeTable = map[string]uint32{
	"":                   ListTypeNone,
	"syscalls":           ListTypeSyscalls,
	"generated_syscalls": ListTypeGeneratedSyscalls,
	"generated_ftrace":   ListTypeGeneratedFtrace,
}

func listTypeFromString(s string) int32 {
	typ, ok := listTypeTable[strings.ToLower(s)]
	if !ok {
		return ListTypeInvalid
	}
	return int32(typ)
}

func isSyscallListType(typ string) bool {
	return listTypeFromString(typ) == ListTypeSyscalls ||
		listTypeFromString(typ) == ListTypeGeneratedSyscalls
}

func validateList(list *v1alpha1.ListSpec) (err error) {
	if listTypeFromString(list.Type) == ListTypeInvalid {
		return fmt.Errorf("Invalid list type: %s", list.Type)
	}

	return fmt.Errorf("not supported on windows")
}

func preValidateLists(lists []v1alpha1.ListSpec) (err error) {
	for i := range lists {
		list := &lists[i]

		if list.Validated {
			continue
		}
		err := validateList(list)
		if err != nil {
			return err
		}
		list.Validated = true
	}
	return nil
}

type listReader struct {
	lists []v1alpha1.ListSpec
}

func (lr *listReader) Read(name string, ty uint32) ([]uint32, error) {
	list := func() *v1alpha1.ListSpec {
		for idx := range lr.lists {
			if lr.lists[idx].Name == name {
				return &lr.lists[idx]
			}
		}
		return nil
	}()

	if list == nil {
		return []uint32{}, fmt.Errorf("Error list '%s' not found", name)
	}
	if !isSyscallListType(list.Type) {
		return []uint32{}, fmt.Errorf("Error list '%s' is not syscall type", name)
	}
	if ty != gt.GenericSyscall64 {
		return []uint32{}, fmt.Errorf("Error list '%s' argument type is not syscall64", name)
	}
	return []uint32{}, fmt.Errorf("Not supported on Windows")
}

func getSyscallListSymbols(list *v1alpha1.ListSpec) ([]string, error) {
	if list.Type != "syscalls" {
		return nil, fmt.Errorf("unexpected error: getSyscallListSymbols was passed a non-syscall list")
	}

	return nil, fmt.Errorf("not supported on Windows")
}

func getListSymbols(list *v1alpha1.ListSpec) ([]string, error) {
	switch list.Type {
	case "syscalls":
		return getSyscallListSymbols(list)
	default:
		return list.Values, nil
	}
}
