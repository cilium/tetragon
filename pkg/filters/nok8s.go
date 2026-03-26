// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package filters

import (
	"context"
	"errors"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type LabelsFilter struct{}

func (l *LabelsFilter) OnBuildFilter(_ context.Context, _ *tetragon.Filter) ([]FilterFunc, error) {
	return nil, errors.New("label filters not supported in nok8s build")
}
