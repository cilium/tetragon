// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"log"
	"strconv"

	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/option"
)

type EnforcerSpecBuilder struct {
	name           string
	syscalls       [][]string
	kill           *uint32
	override       *int32
	binaries       []string
	overrideMethod string
	multiKprobe    *bool
}

func NewEnforcerSpecBuilder(name string) *EnforcerSpecBuilder {
	return &EnforcerSpecBuilder{
		name: name,
	}
}

func (ksb *EnforcerSpecBuilder) WithSyscallList(calls ...string) *EnforcerSpecBuilder {
	ksb.syscalls = append(ksb.syscalls, calls)
	return ksb
}

func (ksb *EnforcerSpecBuilder) WithKill(sig uint32) *EnforcerSpecBuilder {
	ksb.kill = &sig
	return ksb
}

func (ksb *EnforcerSpecBuilder) WithMultiKprobe() *EnforcerSpecBuilder {
	multi := true
	ksb.multiKprobe = &multi
	return ksb
}

func (ksb *EnforcerSpecBuilder) WithoutMultiKprobe() *EnforcerSpecBuilder {
	multi := false
	ksb.multiKprobe = &multi
	return ksb
}

func (ksb *EnforcerSpecBuilder) WithOverrideValue(ret int32) *EnforcerSpecBuilder {
	ksb.override = &ret
	return ksb
}

func (ksb *EnforcerSpecBuilder) WithMatchBinaries(bins ...string) *EnforcerSpecBuilder {
	ksb.binaries = append(ksb.binaries, bins...)
	return ksb
}

func (ksb *EnforcerSpecBuilder) WithOverrideReturn() *EnforcerSpecBuilder {
	ksb.overrideMethod = valOverrideReturn
	return ksb
}

func (ksb *EnforcerSpecBuilder) WithFmodRet() *EnforcerSpecBuilder {
	ksb.overrideMethod = valFmodRet
	return ksb

}

func (ksb *EnforcerSpecBuilder) WithDefaultOverride() *EnforcerSpecBuilder {
	ksb.overrideMethod = ""
	return ksb
}

func (ksb *EnforcerSpecBuilder) MustBuild() *v1alpha1.TracingPolicy {
	spec, err := ksb.Build()
	if err != nil {
		log.Fatalf("MustBuild failed with %v", err)
	}
	return spec
}

func (ksb *EnforcerSpecBuilder) MustYAML() string {
	tp, err := ksb.Build()
	if err != nil {
		log.Fatalf("MustYAML: build failed with %v", err)
	}

	b, err := yaml.Marshal(tp)
	if err != nil {
		log.Fatalf("MustYAML: marshal failed with %v", err)
	}
	return string(b)
}

func (ksb *EnforcerSpecBuilder) Build() (*v1alpha1.TracingPolicy, error) {

	var listNames []string
	var lists []v1alpha1.ListSpec
	var enforcers []v1alpha1.EnforcerSpec
	var matchBinaries []v1alpha1.BinarySelector
	var options []v1alpha1.OptionSpec

	for i, syscallList := range ksb.syscalls {
		var name string
		if len(ksb.syscalls) > 1 {
			name = fmt.Sprintf("%s-%d", ksb.name, i+1)
		} else {
			name = ksb.name
		}
		listName := "list:" + name
		listNames = append(listNames, listName)
		lists = append(lists, v1alpha1.ListSpec{
			Name:      name,
			Type:      "syscalls",
			Values:    syscallList,
			Pattern:   nil,
			Validated: false,
		})
		enforcers = append(enforcers, v1alpha1.EnforcerSpec{
			Calls: []string{listName},
		})
	}

	actions := []v1alpha1.ActionSelector{{Action: "NotifyEnforcer"}}
	act := &actions[0]
	if ksb.kill == nil && ksb.override == nil {
		return nil, errors.New("need either override or kill to notify enforcer")
	}
	if ksb.kill != nil {
		act.ArgSig = *ksb.kill
	}
	if ksb.override != nil {
		act.ArgError = *ksb.override
	}

	if len(ksb.binaries) > 0 {
		matchBinaries = []v1alpha1.BinarySelector{{
			Operator: "In",
			Values:   ksb.binaries,
		}}
	}

	if ksb.overrideMethod != "" {
		options = append(options, v1alpha1.OptionSpec{
			Name:  keyOverrideMethod,
			Value: ksb.overrideMethod,
		})
	}

	if ksb.multiKprobe != nil {
		options = append(options, v1alpha1.OptionSpec{
			Name:  option.KeyDisableKprobeMulti,
			Value: strconv.FormatBool(*ksb.multiKprobe),
		})
	}

	// NB: We might want to add options for these in the future
	syscallIDTy := "syscall64"
	operator := "InMap"

	return &v1alpha1.TracingPolicy{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "TracingPolicy",
			APIVersion: "cilium.io/v1alpha1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name: ksb.name,
		},
		Spec: v1alpha1.TracingPolicySpec{
			Lists: lists,
			Tracepoints: []v1alpha1.TracepointSpec{{
				Subsystem: "raw_syscalls",
				Event:     "sys_enter",
				Args: []v1alpha1.KProbeArg{{
					Index: 4,
					Type:  syscallIDTy,
				}},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchArgs: []v1alpha1.ArgSelector{{
						Index:    0,
						Operator: operator,
						Values:   listNames,
					}},
					MatchActions:  actions,
					MatchBinaries: matchBinaries,
				}},
			}},
			Enforcers: enforcers,
			Options:   options,
		},
	}, nil
}
