// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bench

import (
	"context"
	"fmt"
	"os/exec"
)

type traceBenchCustom struct {
}

func (src traceBenchCustom) Run(_ context.Context, args *Arguments, _ *Summary) error {
	fmt.Printf("running %v\n", args.CmdArgs)

	// run the benchmark
	cmd := exec.Command(args.CmdArgs[0], args.CmdArgs[1:]...)

	// get the result
	var out []byte
	var err error

	out, err = cmd.Output()
	if err != nil {
		fmt.Printf("%s\n", err)
	}
	fmt.Printf("%s\n", out)
	return err
}

func (src traceBenchCustom) ConfigFilename(args *Arguments) string {
	return args.Crd
}

func newTraceBenchCustom() *traceBenchCustom {
	return &traceBenchCustom{}
}
