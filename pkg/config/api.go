// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

type SpecOptions struct {
	DisableKprobeMulti *bool `json:"disable-kprobe-multi,omitempty"`
}

type Spec struct {
	// A list of options
	Options SpecOptions `json:"options,omitempty"`
}
