// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package multistep

// if returns step only if on is true.
func If(on bool, step Step) Step {
	if !on {
		return &nullStep{}
	}
	return step
}
