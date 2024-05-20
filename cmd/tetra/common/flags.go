// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import "time"

const (
	KeyColor         = "color"          // string
	KeyDebug         = "debug"          // bool
	KeyOutput        = "output"         // string
	KeyTty           = "tty-encode"     // string
	KeyServerAddress = "server-address" // string
	KeyTimeout       = "timeout"        // duration
	KeyRetries       = "retries"        // int
	KeyNamespace     = "namespace"      //string
)

const (
	defaultServerAddress = "localhost:54321"
)

var (
	Debug         bool
	ServerAddress string
	Timeout       time.Duration
	Retries       int
)
