// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !linux

package javaattach

import "errors"

func LoadNativeAgent(int, string, string) error {
	return errors.New("Java Attach is supported only on Linux")
}
