// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errormetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/api/ops"
)

func TestHandlePerfEmptyData(t *testing.T) {
	// verify label exists and is correct
	assert.Equal(t, "perf_empty_data", HandlePerfEmptyData.String())

	// use relative comparison to avoid depending on global state from InitMetrics()
	// verify metric initializes to 0
	before := testutil.ToFloat64(GetHandlerErrors(ops.MSG_OP_UNDEF, HandlePerfEmptyData))
	HandlerErrorsInc(ops.MSG_OP_UNDEF, HandlePerfEmptyData)
	after := testutil.ToFloat64(GetHandlerErrors(ops.MSG_OP_UNDEF, HandlePerfEmptyData))
	assert.InDelta(t, before+1, after, 1e-9)
}
