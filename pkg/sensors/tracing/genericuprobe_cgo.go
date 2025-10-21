// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

// Go 1.21 broke dynamic symbol linking export, see more
// https://github.com/golang/go/issues/62520
// https://github.com/golang/go/issues/62520#issuecomment-1712181946
// For unknown reasons --export-dynamic-symbol=uprobe_test_func doesn't work
// with CGO comment, maybe for security reasons, see
// https://pkg.go.dev/cmd/cgo#hdr-Using_cgo_with_the_go_command

// #cgo LDFLAGS: '-Wl,--export-dynamic'
/*
int uprobe_test_func(void)
{
	return 0;
}
*/
import "C"

func UprobeTestFunc() {
	C.uprobe_test_func()
}
