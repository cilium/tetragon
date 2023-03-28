// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
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

/*
func validate(btf bpf.BTF, spec *v1alpha1.KProbeSpec) (bpf.BtfID, error) {

	llCallID, err := btf.FindByNameKind(llCall, bpf.BtfKindFunc)
	if err != nil {
		return bpf.BtfID(0), &ValidationWarn{s: fmt.Sprintf("could not get the function prototype for %s. Arguments will not be verified", spec.Call)}
	}

	llCallTy, err := btf.TypeByID(llCallID)
	if err != nil {
		fmt.Errorf("failed to to find syscall type by id: %w", err)
	}

	return btf.UnderlyingType(llCallTy)
}
*/

func hasSigkillAction(kspec *v1alpha1.KProbeSpec) bool {
	for i := range kspec.Selectors {
		s := &kspec.Selectors[i]
		for j := range s.MatchActions {
			act := strings.ToLower(s.MatchActions[j].Action)
			if act == "sigkill" {
				return true
			}
		}
	}
	return false
}

// ValidateKprobeSpec validates a kprobe spec based on BTF information
//
// NB: turns out we need more than BTF information for the validation (see
// syscalls). We still keep this code in the btf package for now, and we can
// move it once we found a better home for it.
func ValidateKprobeSpec(bspec *btf.Spec, kspec *v1alpha1.KProbeSpec) error {
	if hasSigkillAction(kspec) && !kernels.MinKernelVersion("5.3.0") {
		return &ValidationFailed{s: "sigkill action requires kernel >= 5.3.0"}
	}

	var fn *btf.Func

	err := bspec.TypeByName(kspec.Call, &fn)
	if err != nil {
		return fmt.Errorf("kprobe spec validation failed: call %s not found", kspec.Call)
	}

	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return fmt.Errorf("kprobe spec validation failed: proto for call %s not found", kspec.Call)
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
		if !strings.HasPrefix(kspec.Call, prefix) {
			return &ValidationWarn{s: fmt.Sprintf("could not get the function prototype for %s: arguments will not be verified", kspec.Call)}
		}
		syscall := strings.TrimPrefix(kspec.Call, prefix)
		return validateSyscall(kspec, syscall)
	}

	fnNArgs := uint32(len(proto.Params))
	for i := range kspec.Args {
		specArg := &kspec.Args[i]
		if specArg.Index >= fnNArgs {
			return fmt.Errorf("kprobe arg %d has an invalid index: %d based on prototype: %s", i, specArg.Index, proto)
		}
		arg := proto.Params[int(specArg.Index)]
		err := checkTypesCompatibility(specArg.Type, "", arg.Type)
		if err != nil {
			return &ValidationWarn{s: fmt.Sprintf("validate argument %d failed: %v\n", specArg.Index, err)}
		}
	}

	if kspec.Return {
		err := checkTypesCompatibility(kspec.ReturnArg.Type, "", proto.Return)
		if err != nil {
			return &ValidationWarn{s: fmt.Sprintf("validate return type failed: %v\n", err)}
		}
	}

	return nil
}

func getBtfKernelType(arg btf.Type) string {
	ptr, ok := arg.(*btf.Pointer)
	if ok {
		arg = ptr.Target
	}
	num, ok := arg.(*btf.Int)
	if ok {
		return num.Name
	}
	strct, ok := arg.(*btf.Struct)
	if ok {
		return strct.Name
	}
	// TODO - add more types, above is enough to make validation_test pass
	return arg.TypeName()
}

// checkTypesCompatibility checks if the passed types are compatible
//
// specTy The spec type to check
// kernelTy The kernel type to check against
// btfTy The BTF Type to check against instead of kernelTy
//
// Returns an error if the types are not compatible
func checkTypesCompatibility(specTy string, kernelTy string, btfTy btf.Type) error {
	if btfTy != nil {
		kernelTy = getBtfKernelType(btfTy)
	}

	switch specTy {
	case "size_t":
		switch kernelTy {
		case "size_t":
			return nil
		}
	case "char_buf", "string":
		switch kernelTy {
		case "const char *", "char *":
			return nil
		}
	case "char_iovec":
		switch kernelTy {
		case "const struct iovec *", "struct iovec *":
			return nil
		}
	case "int", "fd":
		switch kernelTy {
		case "unsigned int", "int", "unsigned long", "long":
			return nil
		}
	case "filename":
		switch kernelTy {
		case "struct filename *":
		case "filename":
			return nil
		}
	case "file":
		switch kernelTy {
		case "struct file *":
		case "file":
			return nil
		}
	case "bpf_attr":
		switch kernelTy {
		case "union bpf_attr *":
		case "bpf_attr":
			return nil
		}
	case "perf_event":
		switch kernelTy {
		case "struct perf_event *":
		case "perf_event":
			return nil
		}
	case "bpf_map":
		switch kernelTy {
		case "struct bpf_map *":
		case "bpf_map":
			return nil
		}
	case "user_namespace":
		switch kernelTy {
		case "struct user_namespace *":
		case "user_namespace":
			return nil
		}
	case "capability":
		switch kernelTy {
		case "int":
			return nil
		}
	}

	return fmt.Errorf("type (%s) does not match spec type (%s)", kernelTy, specTy)
}

func validateSyscall(kspec *v1alpha1.KProbeSpec, name string) error {
	if kspec.Return {
		err := checkTypesCompatibility(kspec.ReturnArg.Type, "long", nil)
		if err != nil {
			return fmt.Errorf("validate syscall return type failed: %s", err)
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
		err := checkTypesCompatibility(specArg.Type, argTy, nil)
		if err != nil {
			return &ValidationWarn{s: fmt.Sprintf("validate syscall argument %d failed: %v\n", specArg.Index, err)}
		}
	}

	return nil
}
