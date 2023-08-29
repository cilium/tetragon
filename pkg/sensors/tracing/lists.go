// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/ftrace"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/syscallinfo"
)

func getList(name string, lists []v1alpha1.ListSpec) *v1alpha1.ListSpec {
	for idx := range lists {
		list := &lists[idx]
		if list.Name == name {
			return list
		}
	}
	return nil
}

const (
	ListTypeInvalid           = -1
	ListTypeNone              = 0
	ListTypeSyscalls          = 1
	ListTypeGeneratedSyscalls = 2
	ListTypeGeneratedFtrace   = 3
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

	// Add prefix to syscalls list
	if listTypeFromString(list.Type) == ListTypeSyscalls {
		for idx := range list.Values {
			symbol, err := arch.AddSyscallPrefix(list.Values[idx])
			if err != nil {
				return err
			}
			list.Values[idx] = symbol
		}
		return nil
	}

	// Generate syscalls list
	if listTypeFromString(list.Type) == ListTypeGeneratedSyscalls {
		if len(list.Values) != 0 {
			return fmt.Errorf("Error generated list '%s' has values", list.Name)
		}
		tmp, err := btf.GetSyscallsList()
		if err != nil {
			return err
		}
		list.Values = append(list.Values, tmp...)
		return nil
	}

	// Generate ftrace list
	if listTypeFromString(list.Type) == ListTypeGeneratedFtrace {
		if len(list.Values) != 0 {
			return fmt.Errorf("Error generated list '%s' has values", list.Name)
		}
		if list.Pattern == nil || (list.Pattern != nil && *(list.Pattern) == "") {
			return fmt.Errorf("Error generated ftrace list '%s' must specify pattern", list.Name)
		}
		list.Values, err = ftrace.ReadAvailFuncs(*(list.Pattern))
		return err
	}

	return nil
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

func (lr *listReader) Read(name string) ([]uint32, error) {
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

	var res []uint32

	for idx := range list.Values {
		sc := arch.CutSyscallPrefix(list.Values[idx])
		if strings.HasPrefix(sc, "sys_") {
			sc = sc[len("sys_"):]
		}
		id := syscallinfo.GetSyscallID(sc)
		if id == -1 {
			return []uint32{}, fmt.Errorf("failed list '%s' cannot translate syscall '%s'", name, sc)
		}
		res = append(res, uint32(id))
	}

	return res, nil
}
