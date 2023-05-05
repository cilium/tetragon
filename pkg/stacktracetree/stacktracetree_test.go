// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package stacktracetree

import (
	"fmt"
	"testing"
)

func TestSimple(_ *testing.T) {
	fmt.Printf("Hello!\n")
	stt0 := Stt{}
	stt0.Append(0x10, "", []string{})
	stt0.Append(0x20, "", []string{})
	stt0.Append(0x30, "", []string{})

	stt1 := Stt{}
	stt1.Append(0x10, "", []string{})
	stt1.Append(0x20, "", []string{})
	stt1.Append(0x40, "", []string{})

	tree := CreateSttree()
	tree.AddStacktrace(&stt0)
	tree.Print()
	tree.AddStacktrace(&stt1)
	tree.Print()

}
