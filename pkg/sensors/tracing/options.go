// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyconf"
)

type OverrideMethod int

const (
	keyOverrideMethod = "override-method"
	valFmodRet        = "fmod-ret"
	valOverrideReturn = "override-return"
	keyPolicyMode     = "policy-mode"
)

const (
	OverrideMethodDefault OverrideMethod = iota
	OverrideMethodReturn
	OverrideMethodFmodRet
	OverrideMethodInvalid
)

func overrideMethodParse(s string) OverrideMethod {
	switch s {
	case valFmodRet:
		return OverrideMethodFmodRet
	case valOverrideReturn:
		return OverrideMethodReturn
	default:
		return OverrideMethodInvalid
	}
}

type specOptions struct {
	DisableKprobeMulti bool
	DisableUprobeMulti bool
	OverrideMethod     OverrideMethod
	policyMode         policyconf.Mode
}

type opt struct {
	set func(val string, options *specOptions) error
}

func newDefaultSpecOptions() *specOptions {
	return &specOptions{
		DisableKprobeMulti: false,
		OverrideMethod:     OverrideMethodDefault,
	}
}

// Allowed kprobe options
var opts = map[string]opt{
	option.KeyDisableKprobeMulti: opt{
		set: func(str string, options *specOptions) (err error) {
			options.DisableKprobeMulti, err = strconv.ParseBool(str)
			return err
		},
	},
	option.KeyDisableUprobeMulti: opt{
		set: func(str string, options *specOptions) (err error) {
			options.DisableUprobeMulti, err = strconv.ParseBool(str)
			return err
		},
	},
	keyOverrideMethod: opt{
		set: func(str string, options *specOptions) (err error) {
			m := overrideMethodParse(str)
			if m == OverrideMethodInvalid {
				return fmt.Errorf("invalid override method: '%s'", str)
			}
			options.OverrideMethod = m
			return nil
		},
	},
	keyPolicyMode: opt{
		set: func(str string, options *specOptions) (err error) {
			mode, err := policyconf.ParseMode(str)
			if err != nil {
				return err
			}
			options.policyMode = mode
			return nil
		},
	},
}

func getSpecOptions(specs []v1alpha1.OptionSpec) (*specOptions, error) {
	options := newDefaultSpecOptions()
	for _, spec := range specs {
		opt, ok := opts[spec.Name]
		if ok {
			if err := opt.set(spec.Value, options); err != nil {
				return nil, fmt.Errorf("failed to set option %s: %s", spec.Name, err)
			}
			logger.GetLogger().Infof("Set option %s = %s", spec.Name, spec.Value)
		}
	}
	return options, nil
}
