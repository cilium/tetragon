// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows
// +build !windows

package btf

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/syscallinfo"
)

// ValidationWarn is used to mark that validation was not successful but it's not
// clear that the spec is problematic. Callers may use this error to issue a
// warning instead of aborting
type ValidationWarn struct {
	s string
}

func (e *ValidationWarn) Error() string {
	return e.s
}

// ValidationFailed is used to mark that validation was not successful and that
// the we should not continue with loading this spec.
type ValidationFailed struct {
	s string
}

func (e *ValidationFailed) Error() string {
	return e.s
}

// ValidateKprobeSpec validates a kprobe spec based on BTF information
//
// NB: turns out we need more than BTF information for the validation (see
// syscalls). We still keep this code in the btf package for now, and we can
// move it once we found a better home for it.
func ValidateKprobeSpec(bspec *btf.Spec, call string, kspec *v1alpha1.KProbeSpec, ks *ksyms.Ksyms) error {
	var fn *btf.Func

	// check if this functio name is part of a kernel module
	if kmod, err := ks.GetKmod(call); err == nil {
		// get the spec from the kernel module and continue the validation with that
		kmodSpec, err := btf.LoadKernelModuleSpec(kmod)
		if err != nil {
			return fmt.Errorf("validateKprobeSpec: btf.LoadKernelModuleSpec: %w", err)
		}
		bspec = kmodSpec
	}

	origCall := call
	err := bspec.TypeByName(call, &fn)
	if err != nil && kspec.Syscall {
		// Try with system call prefix
		call, err = arch.AddSyscallPrefix(call)
		if err == nil {
			err = bspec.TypeByName(call, &fn)
		}
	}

	// BTF include multiple candidates
	if errors.Is(err, btf.ErrMultipleMatches) {
		var allTypes, fnTypes []btf.Type
		allTypes, err = bspec.AnyTypesByName(call)
		if err == nil {
			for _, typ := range allTypes {
				// Assert again the appropriate type
				if _, ok := typ.(*btf.Func); ok {
					fnTypes = append(fnTypes, typ)
				}
			}
			// TypeByName() above ensures btf.Func type, but Check again so semantically we are correct
			if len(fnTypes) > 0 {
				logger.GetLogger().Infof("BTF metadata includes '%d' matched candidates on call %q, using first one", len(fnTypes), call)
				// take first one.
				reflect.ValueOf(&fn).Elem().Set(reflect.ValueOf(fnTypes[0]))
			}
		}
	}

	if err != nil {
		if kspec.Syscall {
			return &ValidationFailed{
				s: fmt.Sprintf("syscall %q (or %q) %v", origCall, call, err),
			}
		}
		return &ValidationFailed{s: fmt.Sprintf("call %q %v", call, err)}
	}

	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return fmt.Errorf("kprobe spec validation failed: proto for call %s not found", call)
	}

	// Syscalls are special.
	// We (at least in recent kernels) hook into __x64_sys_FOO for
	// syscalls, but this function's signature does not allow us to check
	// arguments. Moreover, the does not seem to be a reliable way of doing
	// so with our BTF files.
	if kspec.Syscall {
		ret, ok := proto.Return.(*btf.Int)
		if !ok {
			return fmt.Errorf("kprobe spec validation failed: syscall return type is not Int")
		}
		if ret.Name != "long int" {
			return fmt.Errorf("kprobe spec validation failed: syscall return type is not long int")
		}

		if len(proto.Params) != 1 {
			return fmt.Errorf("kprobe spec validation failed: syscall with more than one arg")
		}

		ptr, ok := proto.Params[0].Type.(*btf.Pointer)
		if !ok {
			return fmt.Errorf("kprobe spec validation failed: syscall arg is not pointer")
		}

		cnst, ok := ptr.Target.(*btf.Const)
		if !ok {
			return fmt.Errorf("kprobe spec validation failed: syscall arg is not const pointer")
		}

		arg, ok := cnst.Type.(*btf.Struct)
		if !ok {
			return fmt.Errorf("kprobe spec validation failed: syscall arg is not const pointer to struct")
		}

		if arg.Name != "pt_regs" {
			return fmt.Errorf("kprobe spec validation failed: syscall arg is not const pointer to struct pt_regs")
		}

		// next try to deduce the syscall name.
		// NB: this might change in different kernels so if we fail we treat it as a warning
		prefix := "__x64_sys_"
		if !strings.HasPrefix(call, prefix) {
			return &ValidationWarn{s: fmt.Sprintf("could not get the function prototype for %s: arguments will not be verified", call)}
		}
		syscall := strings.TrimPrefix(call, prefix)
		return validateSycall(kspec, syscall)
	}

	fnNArgs := uint32(len(proto.Params))
	for i := range kspec.Args {
		specArg := &kspec.Args[i]
		if specArg.Index >= fnNArgs {
			return fmt.Errorf("kprobe arg %d has an invalid index: %d based on prototype: %s", i, specArg.Index, proto)
		}
		arg := proto.Params[int(specArg.Index)]
		paramTyStr := getKernelType(arg.Type)
		if !typesCompatible(specArg.Type, paramTyStr) {
			return &ValidationWarn{s: fmt.Sprintf("type (%s) of argument %d does not match spec type (%s)\n", paramTyStr, specArg.Index, specArg.Type)}
		}
	}

	if kspec.Return {
		retTyStr := getKernelType(proto.Return)
		if kspec.ReturnArg == nil {
			return &ValidationWarn{s: "return is set to true, but there is no return arg specified"}
		}
		if !typesCompatible(kspec.ReturnArg.Type, retTyStr) {
			return &ValidationWarn{s: fmt.Sprintf("return type (%s) does not match spec return type (%s)\n", retTyStr, kspec.ReturnArg.Type)}
		}
	}

	return nil
}

func getKernelType(arg btf.Type) string {
	suffix := ""
	ptr, ok := arg.(*btf.Pointer)
	if ok {
		arg = ptr.Target
		_, ok = arg.(*btf.Void)
		if ok {
			return "void *"
		}
		suffix = suffix + " *"
	}
	num, ok := arg.(*btf.Int)
	if ok {
		return num.Name + suffix
	}
	strct, ok := arg.(*btf.Struct)
	if ok {
		return "struct " + strct.Name + suffix
	}

	union, ok := arg.(*btf.Union)
	if ok {
		return "union " + union.Name + suffix
	}

	enum, ok := arg.(*btf.Enum)
	if ok {
		prefix := "u"
		if enum.Signed {
			prefix = "s"
		}
		switch enum.Size {
		case 1:
		case 2:
		case 4:
		case 8:
		default:
			// Not sure what to do here, so just dump the type name
			return arg.TypeName() + suffix
		}
		return fmt.Sprintf("%s%d%s", prefix, 8*enum.Size, suffix)
	}

	cnst, ok := arg.(*btf.Const)
	if ok {
		// NB: ignore const
		ty := cnst.Type
		if ptr != nil {
			// NB: if this was a pointer, reconstruct the type without const
			ty = &btf.Pointer{
				Target: ty,
			}
		}
		return getKernelType(ty)
	}

	// TODO - add more types, above is enough to make validation_test pass
	return arg.TypeName() + suffix
}

func typesCompatible(specTy string, kernelTy string) bool {
	switch specTy {
	case "nop":
		return true

	case "uint64":
		switch kernelTy {
		case "u64", "void *", "long unsigned int":
			return true
		}
	case "int64":
		switch kernelTy {
		case "s64":
			return true
		}
	case "int32":
		switch kernelTy {
		case "s32", "int":
			return true
		}
	case "int16":
		switch kernelTy {
		case "s16", "short int":
			return true
		}
	case "uint16":
		switch kernelTy {
		case "u16", "short unsigned int":
			return true
		}
	case "uint8":
		switch kernelTy {
		case "u8", "unsigned char":
			return true
		}
	case "size_t":
		switch kernelTy {
		case "size_t":
			return true
		}
	case "char_buf", "string", "int8":
		switch kernelTy {
		case "const char *", "char *", "char":
			return true
		}
	case "char_iovec":
		switch kernelTy {
		case "const struct iovec *", "struct iovec *":
			return true
		}
	case "fd":
		switch kernelTy {
		case "unsigned int", "int", "unsigned long", "long":
			return true
		}
	case "int":
		switch kernelTy {
		case "unsigned int", "int", "unsigned long", "long", "uid_t", "gid_t", "u32", "s32":
			return true
		}
	case "filename":
		switch kernelTy {
		case "struct filename *":
			return true
		}
	case "file":
		switch kernelTy {
		case "struct file *":
			return true
		}
	case "path":
		switch kernelTy {
		case "struct path *":
			return true
		}
	case "bpf_attr":
		switch kernelTy {
		case "union bpf_attr *":
			return true
		}
	case "perf_event":
		switch kernelTy {
		case "struct perf_event *":
			return true
		}
	case "bpf_map":
		switch kernelTy {
		case "struct bpf_map *":
			return true
		}
	case "user_namespace":
		switch kernelTy {
		case "struct user_namespace *":
			return true
		}
	case "capability", "bpf_cmd":
		switch kernelTy {
		case "int":
			return true
		}
	case "cred":
		switch kernelTy {
		case "struct cred *":
			return true
		}
	case "linux_binprm":
		switch kernelTy {
		case "struct linux_binprm *":
			return true
		}
	case "load_info":
		switch kernelTy {
		case "struct load_info *":
			return true
		}
	case "module":
		switch kernelTy {
		case "struct module *":
			return true
		}
	case "sock":
		switch kernelTy {
		case "struct sock *":
			return true
		}
	case "skb":
		switch kernelTy {
		case "struct sk_buff *":
			return true
		}
	case "sockaddr":
		switch kernelTy {
		case "struct sockaddr *":
			return true
		}
	case "socket":
		switch kernelTy {
		case "struct socket *":
			return true
		}
	case "net_device":
		switch kernelTy {
		case "struct net_device *":
			return true
		}
	case "kernel_cap_t", "cap_inheritable", "cap_permitted", "cap_effective":
		switch kernelTy {
		case "struct kernel_cap_t *":
			return true
		}
	}

	return false
}

func validateSycall(kspec *v1alpha1.KProbeSpec, name string) error {
	if kspec.Return {
		if kspec.ReturnArg == nil {
			return fmt.Errorf("missing information for syscall %s: returnArg is missing", name)
		}
		if !typesCompatible(kspec.ReturnArg.Type, "long") {
			return fmt.Errorf("unexpected syscall spec return type: %s", kspec.ReturnArg.Type)
		}
	}

	argsInfo, ok := syscallinfo.GetSyscallArgs(name)
	if !ok {
		return &ValidationWarn{s: fmt.Sprintf("missing information for syscall %s: arguments will not be verified", name)}
	}

	for i := range kspec.Args {
		specArg := &kspec.Args[i]
		if specArg.Index >= uint32(len(argsInfo)) {
			return fmt.Errorf("kprobe arg %d has an invalid index: %d based on prototype: %s", i, specArg.Index, argsInfo.Proto(name))
		}

		argTy := argsInfo[specArg.Index].Type
		if !typesCompatible(specArg.Type, argTy) {
			return &ValidationWarn{s: fmt.Sprintf("type (%s) of syscall argument %d does not match spec type (%s)\n", argTy, specArg.Index, specArg.Type)}
		}
	}

	return nil
}

// AvailableSyscalls returns the list of available syscalls.
//
// It uses syscallinfo.SyscallsNames() and filters calls via information in BTF.
func AvailableSyscalls() ([]string, error) {
	// NB(kkourt): we should have a single function for this (see observerFindBTF)
	btfFile := "/sys/kernel/btf/vmlinux"
	tetragonBtfEnv := os.Getenv("TETRAGON_BTF")
	if tetragonBtfEnv != "" {
		if _, err := os.Stat(tetragonBtfEnv); err != nil {
			return nil, fmt.Errorf("Failed to find BTF: %s", tetragonBtfEnv)
		}
		btfFile = tetragonBtfEnv
	}
	bspec, err := btf.LoadSpec(btfFile)
	if err != nil {
		return nil, fmt.Errorf("BTF load failed: %v", err)
	}

	ret := []string{}
	abi, err := syscallinfo.DefaultABI()
	if err != nil {
		return nil, err
	}
	names, err := syscallinfo.SyscallsNames(abi)
	if err != nil {
		return nil, err
	}
	for key, value := range names {
		if value == "" {
			return nil, fmt.Errorf("syscall name for %q is empty", key)
		}

		sym, err := arch.AddSyscallPrefix(value)
		if err != nil {
			return nil, err
		}

		var fn *btf.Func
		if err = bspec.TypeByName(sym, &fn); err != nil {
			continue
		}

		ret = append(ret, value)
	}

	return ret, nil
}

func GetSyscallsList() ([]string, error) {
	btfFile := "/sys/kernel/btf/vmlinux"

	tetragonBtfEnv := os.Getenv("TETRAGON_BTF")
	if tetragonBtfEnv != "" {
		if _, err := os.Stat(tetragonBtfEnv); err != nil {
			return []string{}, fmt.Errorf("Failed to find BTF: %s", tetragonBtfEnv)
		}
		btfFile = tetragonBtfEnv
	}

	bspec, err := btf.LoadSpec(btfFile)
	if err != nil {
		return []string{}, fmt.Errorf("BTF load failed: %v", err)
	}

	var list []string

	abi, err := syscallinfo.DefaultABI()
	if err != nil {
		return nil, err
	}
	names, err := syscallinfo.SyscallsNames(abi)
	if err != nil {
		return nil, err
	}
	for _, value := range names {
		var fn *btf.Func
		sym, err := arch.AddSyscallPrefix(fmt.Sprint("sys_", value))
		if err != nil {
			return []string{}, err
		}

		err = bspec.TypeByName(sym, &fn)
		if err != nil {
			continue
		}

		list = append(list, sym)
	}

	return list, nil
}
