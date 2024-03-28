// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import "github.com/cilium/tetragon/pkg/option"

func OptionsReconfig(spec Spec) {
	if spec.Options.DisableKprobeMulti != nil {
		option.Config.DisableKprobeMulti = *spec.Options.DisableKprobeMulti
	}
}
