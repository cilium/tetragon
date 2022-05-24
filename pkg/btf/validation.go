// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
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
func ValidateKprobeSpec(btf bpf.BTF, kspec *v1alpha1.KProbeSpec) error {
	if hasSigkillAction(kspec) && !kernels.MinKernelVersion("5.3.0") {
		return &ValidationFailed{s: "sigkill action requires kernel >= 5.3.0"}
	}

	// check that the function itself exists
	callID, err := btf.FindByNameKind(kspec.Call, bpf.BtfKindFunc)
	if err != nil {
		return fmt.Errorf("kprobe spec validation failed: call %s not found: %w", kspec.Call, err)
	}
	callTy, err := btf.TypeByID(callID)
	if err != nil {
		logger.GetLogger().WithError(err).Debug("failed to find type by id")
	}

	callProtoID, err := btf.UnderlyingType(callTy)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("call", kspec.Call).Debug("failed to find prototype")
	}

	// Syscalls are special.
	// We (at least in recent kernels) hook into __x64_sys_FOO for
	// syscalls, but this function's signature does not allow us to check
	// arguments. Moreover, the does not seem to be a reliable way of doing
	// so with our BTF files.
	if kspec.Syscall {
		// first validate that the call's signature is what we would expect from a syscall
		s, err := btf.DumpTy(callProtoID)
		if err != nil {
			return fmt.Errorf("validating syscall: %w", err)
		}
		if s != "long int(const struct pt_regs *regs)" {
			return fmt.Errorf("function signature '%s' does not look like a syscall", s)
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

	callProtoTy, err := btf.TypeByID(callProtoID)
	if err != nil {
		logger.GetLogger().WithError(err).Debug("failed to find type by id")
	}

	callProtoStr, err := btf.DumpTy(callProtoID)
	if err != nil {
		logger.GetLogger().WithError(err).Debug("failed to dump function prototype by id")
	}

	fnNArgs := uint32(callProtoTy.Vlen())
	for i := range kspec.Args {
		specArg := &kspec.Args[i]
		if specArg.Index >= fnNArgs {
			return fmt.Errorf("kprobe arg %d has an invalid index: %d based on prototype: %s", i, specArg.Index, callProtoStr)
		}

		paramID, err := btf.ParamTypeID(callProtoTy, int(specArg.Index))
		if err != nil {
			return fmt.Errorf("failed to get paramater type for kprobe arg %d on prototype: %s", i, callProtoStr)
		}

		paramTyStr, err := btf.DumpTy(paramID)
		if err != nil {
			return fmt.Errorf("failed to dump paramemter type by id: %w", err)
		}

		if !typesCompatible(specArg.Type, paramTyStr) {
			return &ValidationWarn{s: fmt.Sprintf("type (%s) of argument %d does not match spec type (%s)\n", paramTyStr, specArg.Index, specArg.Type)}
		}
	}

	if kspec.Return {
		retID, err := btf.UnderlyingType(callProtoTy)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("call", kspec.Call).Debug("failed to find return type")
		}
		retTyStr, err := btf.DumpTy(retID)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("call", kspec.Call).Debug("failed to dump return type")
		}
		if !typesCompatible(kspec.ReturnArg.Type, retTyStr) {
			return &ValidationWarn{s: fmt.Sprintf("return type (%s) does not match spec return type (%s)\n", retTyStr, kspec.ReturnArg.Type)}
		}
	}

	return nil
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
