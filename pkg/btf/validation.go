// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/arch"
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
	if hasSigkillAction(kspec) && !kernels.EnableLargeProgs() {
		return &ValidationFailed{s: "sigkill action requires kernel >= 5.3.0"}
	}

	var fn *btf.Func

	err := bspec.TypeByName(kspec.Call, &fn)
	if err != nil {
		return &ValidationFailed{s: fmt.Sprintf("call %q not found", kspec.Call)}
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
		if !typesCompatible(kspec.ReturnArg.Type, retTyStr) {
			return &ValidationWarn{s: fmt.Sprintf("return type (%s) does not match spec return type (%s)\n", retTyStr, kspec.ReturnArg.Type)}
		}
	}

	return nil
}

func getKernelType(arg btf.Type) string {
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

func typesCompatible(specTy string, kernelTy string) bool {
	switch specTy {
	case "size_t":
		switch kernelTy {
		case "size_t":
			return true
		}
	case "char_buf", "string":
		switch kernelTy {
		case "const char *", "char *":
			return true
		}
	case "char_iovec":
		switch kernelTy {
		case "const struct iovec *", "struct iovec *":
			return true
		}
	case "int", "fd":
		switch kernelTy {
		case "unsigned int", "int", "unsigned long", "long":
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
	case "capability":
		switch kernelTy {
		case "int":
			return true
		}
	}

	return false
}

func validateSycall(kspec *v1alpha1.KProbeSpec, name string) error {
	if kspec.Return {
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

func GetSyscallsYaml(binary string) (string, error) {
	crd := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "syscalls"
spec:
  kprobes:`

	btfFile := "/sys/kernel/btf/vmlinux"

	tetragonBtfEnv := os.Getenv("TETRAGON_BTF")
	if tetragonBtfEnv != "" {
		if _, err := os.Stat(tetragonBtfEnv); err != nil {
			return "", fmt.Errorf("Failed to find BTF: %s", tetragonBtfEnv)
		}
		btfFile = tetragonBtfEnv
	}

	bspec, err := btf.LoadSpec(btfFile)
	if err != nil {
		return "", fmt.Errorf("BTF load failed: %v", err)
	}

	for _, key := range syscallinfo.SyscallsNames() {
		var fn *btf.Func

		if key == "" {
			continue
		}

		sym, err := arch.AddSyscallPrefix(key)
		if err != nil {
			return "", err
		}

		err = bspec.TypeByName(sym, &fn)
		if err != nil {
			continue
		}

		crd = crd + "\n" + fmt.Sprintf("  - call: \"%s\"", key)
		crd = crd + "\n" + fmt.Sprintf("    syscall: true")

		if binary != "" {
			filter := `
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + binary + `"`

			crd = crd + filter
		}
	}

	return crd, nil
}
