// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

// Config contains all the configuration used by TETRAGON.
var Config = config{
	// Initialize global defaults below.

	// ProcFS defaults to /proc.
	ProcFS: "/proc",

	// LogOpts contains logger parameters
	LogOpts: make(map[string]string),
}

type config struct {
	Debug              bool
	ProcFS             string
	KernelVersion      string
	HubbleLib          string
	BTF                string
	Verbosity          int
	IgnoreMissingProgs bool
	ForceSmallProgs    bool

	LogOpts map[string]string
}
