// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package generictypes

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
)

const (
	GenericIntType    = 1
	GenericCharBuffer = 2
	GenericCharIovec  = 3
	GenericSizeType   = 4
	GenericSkbType    = 5
	GenericStringType = 6
	GenericSockType   = 7
	GenericCredType   = 8

	GenericS64Type = 10
	GenericU64Type = 11
	GenericS32Type = 12
	GenericU32Type = 13

	GenericFilenameType = 14
	GenericPathType     = 15
	GenericFileType     = 16
	GenericFdType       = 17

	// GenericConstBuffer is a buffer type whose size is static (and known).
	GenericConstBuffer   = 18
	GenericBpfAttr       = 19
	GenericPerfEvent     = 20
	GenericBpfMap        = 21
	GenericUserNamespace = 22
	GenericCapability    = 23

	GenericKiocb   = 24
	GenericIovIter = 25

	GenericLoadModule   = 26
	GenericKernelModule = 27

	GenericSyscall64 = 28

	GenericS16Type = 29
	GenericU16Type = 30
	GenericS8Type  = 31
	GenericU8Type  = 32

	GenericKernelCap      = 33
	GenericCapInheritable = 34
	GenericCapPermitted   = 35
	GenericCapEffective   = 36

	GenericLinuxBinprmType = 37

	GenericDataLoc = 38

	GenericNetDev = 39

	GenericSockaddrType = 40
	GenericSocketType   = 41

	GenericDentryType = 42

	GenericBpfProgType = 43
	GenericInt32ArrType = 44

	GenericUnsetType   = 0
	GenericNopType     = -1
	GenericInvalidType = -2
)

// Userspace pretty printer types.
const (
	GenericUserBpfCmdType = 1
)

var genericStringToType = map[string]int{
	"string":          GenericStringType,
	"int":             GenericIntType,
	"uint64":          GenericU64Type,
	"unsigned long":   GenericU64Type,
	"ulong":           GenericU64Type,
	"uint32":          GenericU32Type,
	"sint64":          GenericS64Type,
	"int64":           GenericS64Type,
	"long":            GenericS64Type,
	"sint32":          GenericS32Type,
	"int32":           GenericS32Type,
	"skb":             GenericSkbType,
	"sock":            GenericSockType,
	"size_t":          GenericSizeType,
	"char_buf":        GenericCharBuffer,
	"char_iovec":      GenericCharIovec,
	"filename":        GenericFilenameType,
	"file":            GenericFileType,
	"path":            GenericPathType,
	"fd":              GenericFdType,
	"cred":            GenericCredType,
	"const_buf":       GenericConstBuffer,
	"nop":             GenericNopType,
	"bpf_attr":        GenericBpfAttr,
	"perf_event":      GenericPerfEvent,
	"bpf_map":         GenericBpfMap,
	"user_namespace":  GenericUserNamespace,
	"capability":      GenericCapability,
	"kiocb":           GenericKiocb,
	"iov_iter":        GenericIovIter,
	"load_info":       GenericLoadModule,
	"module":          GenericKernelModule,
	"syscall64":       GenericSyscall64,
	"sint16":          GenericS16Type,
	"int16":           GenericS16Type,
	"uint16":          GenericU16Type,
	"sint8":           GenericS8Type,
	"int8":            GenericS8Type,
	"uint8":           GenericU8Type,
	"kernel_cap_t":    GenericKernelCap,
	"cap_inheritable": GenericCapInheritable,
	"cap_permitted":   GenericCapPermitted,
	"cap_effective":   GenericCapEffective,
	"linux_binprm":    GenericLinuxBinprmType,
	"data_loc":        GenericDataLoc,
	"net_device":      GenericNetDev,
	"sockaddr":        GenericSockaddrType,
	"socket":          GenericSocketType,
	"dentry":          GenericDentryType,
	"bpf_prog":        GenericBpfProgType,
	"int32_arr":       GenericInt32ArrType,
}

var genericTypeToStringTable = map[int]string{
	GenericStringType:      "string",
	GenericIntType:         "int",
	GenericU64Type:         "uint64",
	GenericU32Type:         "uint32",
	GenericS64Type:         "int64",
	GenericS32Type:         "int32",
	GenericSkbType:         "skb",
	GenericSockType:        "sock",
	GenericSizeType:        "size_t",
	GenericCharBuffer:      "char_buf",
	GenericCharIovec:       "char_iovec",
	GenericFilenameType:    "filename",
	GenericFileType:        "file",
	GenericPathType:        "path",
	GenericFdType:          "fd",
	GenericCredType:        "cred",
	GenericConstBuffer:     "const_buf",
	GenericNopType:         "nop",
	GenericBpfAttr:         "bpf_attr",
	GenericPerfEvent:       "perf_event",
	GenericBpfMap:          "bpf_map",
	GenericUserNamespace:   "user_namespace",
	GenericCapability:      "capability",
	GenericKiocb:           "kiocb",
	GenericIovIter:         "iov_iter",
	GenericLoadModule:      "load_info",
	GenericKernelModule:    "module",
	GenericSyscall64:       "syscall64",
	GenericS16Type:         "int16",
	GenericU16Type:         "uint16",
	GenericS8Type:          "int8",
	GenericU8Type:          "uint8",
	GenericKernelCap:       "kernel_cap_t",
	GenericCapInheritable:  "cap_inheritable",
	GenericCapPermitted:    "cap_permitted",
	GenericCapEffective:    "cap_effective",
	GenericLinuxBinprmType: "linux_binprm",
	GenericDataLoc:         "data_loc",
	GenericNetDev:          "net_device",
	GenericSockaddrType:    "sockaddr",
	GenericSocketType:      "socket",
	GenericDentryType:      "dentry",
	GenericBpfProgType:     "bpf_prog",
	GenericInvalidType:     "",
}

var genericUserStringToType = map[string]int{
	"bpf_cmd": GenericUserBpfCmdType,
}

var GenericUserToKernel = map[int]int{
	GenericUserBpfCmdType: GenericIntType,
}

var GenericUserTypeToStringTable = map[int]string{
	GenericUserBpfCmdType: "bpf_cmd",
	GenericInvalidType:    "",
}

func GenericUserTypeFromString(arg string) int {
	ty, ok := genericUserStringToType[arg]
	if !ok {
		ty = GenericInvalidType
	}
	return ty
}

func GenericUserToKernelType(arg int) int {
	ty, ok := GenericUserToKernel[arg]
	if !ok {
		ty = GenericInvalidType
	}
	return ty
}

func GenericTypeFromBTF(arg btf.Type) int {
	ty, ok := genericStringToType[arg.TypeName()]
	if !ok {
		switch t := arg.(type) {
		case *btf.Restrict:
			return GenericTypeFromBTF(t.Type)
		case *btf.Volatile:
			return GenericTypeFromBTF(t.Type)
		case *btf.Const:
			return GenericTypeFromBTF(t.Type)
		case *btf.Typedef:
			return GenericTypeFromBTF(t.Type)
		case *btf.Pointer:
			return GenericTypeFromBTF(t.Target)
		default:
			return GenericInvalidType
		}
	}
	return ty
}

func GenericTypeFromString(arg string) int {
	ty, ok := genericStringToType[arg]
	if !ok {
		ty = GenericInvalidType
	}
	return ty
}

// GenericUserTypeToString() converts the passed argument type
// to its string representation.
// Returns empty string on non valid types.
func GenericUserTypeToString(ty int) string {
	return GenericUserTypeToStringTable[ty]
}

func GenericTypeString(ty int) string {
	arg, ok := genericTypeToStringTable[ty]
	if !ok {
		return fmt.Sprintf("unknown type [%d]", ty)
	}
	return arg
}

func GenericTypeToString(ty int) (string, error) {
	arg, ok := genericTypeToStringTable[ty]
	if !ok {
		return "", errors.New("invalid argument type")
	}
	return arg, nil
}

func PathType(ty int) bool {
	return ty == GenericPathType ||
		ty == GenericFileType ||
		ty == GenericDentryType ||
		ty == GenericLinuxBinprmType ||
		ty == GenericKiocb
}
