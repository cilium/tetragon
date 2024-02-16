// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"log"

	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/option"
)

type KillerSpecBuilder struct {
	name           string
	syscalls       [][]string
	kill           *uint32
	override       *int32
	binaries       []string
	overrideMethod string
	multiKprobe    *bool
}

func NewKillerSpecBuilder(name string) *KillerSpecBuilder {
	return &KillerSpecBuilder{
		name: name,
	}
}

func (ksb *KillerSpecBuilder) WithSyscallList(calls ...string) *KillerSpecBuilder {
	ksb.syscalls = append(ksb.syscalls, calls)
	return ksb
}

func (ksb *KillerSpecBuilder) WithKill(sig uint32) *KillerSpecBuilder {
	ksb.kill = &sig
	return ksb
}

func (ksb *KillerSpecBuilder) WithMultiKprobe() *KillerSpecBuilder {
	multi := true
	ksb.multiKprobe = &multi
	return ksb
}

func (ksb *KillerSpecBuilder) WithoutMultiKprobe() *KillerSpecBuilder {
	multi := false
	ksb.multiKprobe = &multi
	return ksb
}

func (ksb *KillerSpecBuilder) WithOverrideValue(ret int32) *KillerSpecBuilder {
	ksb.override = &ret
	return ksb
}

func (ksb *KillerSpecBuilder) WithMatchBinaries(bins ...string) *KillerSpecBuilder {
	ksb.binaries = append(ksb.binaries, bins...)
	return ksb
}

func (ksb *KillerSpecBuilder) WithOverrideReturn() *KillerSpecBuilder {
	ksb.overrideMethod = valOverrideReturn
	return ksb
}

func (ksb *KillerSpecBuilder) WithFmodRet() *KillerSpecBuilder {
	ksb.overrideMethod = valFmodRet
	return ksb

}

func (ksb *KillerSpecBuilder) WithDefaultOverride() *KillerSpecBuilder {
	ksb.overrideMethod = ""
	return ksb
}

func (ksb *KillerSpecBuilder) MustBuild() *v1alpha1.TracingPolicy {
	spec, err := ksb.Build()
	if err != nil {
		log.Fatalf("MustBuild failed with %v", err)
	}
	return spec
}

func (ksb *KillerSpecBuilder) MustYAML() string {
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

func (ksb *KillerSpecBuilder) Build() (*v1alpha1.TracingPolicy, error) {

	var listNames []string
	var lists []v1alpha1.ListSpec
	var killers []v1alpha1.EnforcerSpec
	var matchBinaries []v1alpha1.BinarySelector
	var options []v1alpha1.OptionSpec

	for i, syscallList := range ksb.syscalls {
		var name string
		if len(ksb.syscalls) > 1 {
			name = fmt.Sprintf("%s-%d", ksb.name, i+1)
		} else {
			name = ksb.name
		}
		listName := fmt.Sprintf("list:%s", name)
		listNames = append(listNames, listName)
		lists = append(lists, v1alpha1.ListSpec{
			Name:      name,
			Type:      "syscalls",
			Values:    syscallList,
			Pattern:   nil,
			Validated: false,
		})
		killers = append(killers, v1alpha1.EnforcerSpec{
			Calls: []string{listName},
		})
	}

	actions := []v1alpha1.ActionSelector{{Action: "NotifyKiller"}}
	act := &actions[0]
	if ksb.kill == nil && ksb.override == nil {
		return nil, fmt.Errorf("need either override or kill to notify killer")
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
			Value: fmt.Sprintf("%t", *ksb.multiKprobe),
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
			Enforcers: killers,
			Options:   options,
		},
	}, nil
}
