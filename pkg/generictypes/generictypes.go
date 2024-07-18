// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package generictypes

import "fmt"

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

	GenericDentryType = 40

	GenericNopType     = -1
	GenericInvalidType = -2
)

var GenericStringToType = map[string]int{
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
	"dentry":          GenericDentryType,
}

var GenericTypeToStringTable = map[int]string{
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
	GenericDentryType:      "dentry",
	GenericInvalidType:     "",
}

func GenericTypeFromString(arg string) int {
	ty, ok := GenericStringToType[arg]
	if !ok {
		ty = GenericInvalidType
	}
	return ty
}

func GenericTypeToString(ty int) (string, error) {
	arg, ok := GenericTypeToStringTable[ty]
	if !ok {
		return "", fmt.Errorf("invalid argument type")
	}
	return arg, nil
}
