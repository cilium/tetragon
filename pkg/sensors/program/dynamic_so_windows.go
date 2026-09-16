// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

// Since this is embedded into Program, we need to define it for windows too.
// Just a mock since we don't need anything related on windows.
type DynamicOverride struct{}
