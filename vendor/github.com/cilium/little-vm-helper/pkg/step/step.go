// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package step

import "context"

type Result int

const (
	ResultInvalid Result = iota
	Continue
	Stop
)

type Step interface {
	Do(ctx context.Context) (Result, error)
	Cleanup(ctx context.Context)
}

func DoSteps(ctx context.Context, steps []Step) error {
	for i := range steps {
		res, err := steps[i].Do(ctx)
		if res == Stop || err != nil {
			return err
		}
		defer steps[i].Cleanup(ctx)
	}

	return nil
}
