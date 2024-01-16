// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package generictypes

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

	GenericLinuxBinprmType = 29

	GenericNopType     = -1
	GenericInvalidType = -2
)

func GenericTypeFromString(arg string) int {
	switch arg {
	case "string":
		return GenericStringType
	case "int":
		return GenericIntType
	case "uint64", "unsigned long", "ulong":
		return GenericU64Type
	case "uint32":
		return GenericU32Type
	case "sint64", "int64", "long":
		return GenericS64Type
	case "sint32", "int32":
		return GenericS32Type
	case "skb":
		return GenericSkbType
	case "sock":
		return GenericSockType
	case "size_t":
		return GenericSizeType
	case "char_buf":
		return GenericCharBuffer
	case "char_iovec":
		return GenericCharIovec
	case "filename":
		return GenericFilenameType
	case "file":
		return GenericFileType
	case "path":
		return GenericPathType
	case "fd":
		return GenericFdType
	case "cred":
		return GenericCredType
	case "const_buf":
		return GenericConstBuffer
	case "nop":
		return GenericNopType
	case "bpf_attr":
		return GenericBpfAttr
	case "perf_event":
		return GenericPerfEvent
	case "bpf_map":
		return GenericBpfMap
	case "user_namespace":
		return GenericUserNamespace
	case "capability":
		return GenericCapability
	case "kiocb":
		return GenericKiocb
	case "iov_iter":
		return GenericIovIter
	case "load_info":
		return GenericLoadModule
	case "module":
		return GenericKernelModule
	case "syscall64":
		return GenericSyscall64
	case "linux_binprm":
		return GenericLinuxBinprmType
	default:
		return GenericInvalidType
	}
}
