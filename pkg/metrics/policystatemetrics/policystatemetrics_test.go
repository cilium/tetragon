// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policystatemetrics

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/observer"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_policyStatusCollector_Collect(t *testing.T) {
	expectedMetrics := func(disabled, enabled, err, load_error int) io.Reader {
		return strings.NewReader(fmt.Sprintf(`# HELP tetragon_tracingpolicy_loaded The number of loaded tracing policy by state.
# TYPE tetragon_tracingpolicy_loaded gauge
tetragon_tracingpolicy_loaded{state="disabled"} %d
tetragon_tracingpolicy_loaded{state="enabled"} %d
tetragon_tracingpolicy_loaded{state="error"} %d
tetragon_tracingpolicy_loaded{state="load_error"} %d
`, disabled, enabled, err, load_error))
	}

	reg := prometheus.NewRegistry()

	// NB(kkourt): the policy state collector uses observer.GetSensorManager() to get the sensor
	// manager because in the observer tests we only initialize metrics while the observer
	// changes for every test (see:
	// https://github.com/cilium/tetragon/blob/22eb995b19207ac0ced2dd83950ec8e8aedd122d/pkg/observer/observertesthelper/observer_test_helper.go#L272-L276)
	manager := tus.GetTestSensorManager(context.TODO(), t).Manager
	observer.SetSensorManager(manager)
	t.Cleanup(observer.ResetSensorManager)

	collector := NewPolicyStateCollector()
	reg.Register(collector)

	err := manager.AddTracingPolicy(context.TODO(), &tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "pizza",
		},
	})
	assert.NoError(t, err)
	err = testutil.CollectAndCompare(collector, expectedMetrics(0, 1, 0, 0))
	assert.NoError(t, err)

	err = manager.DisableTracingPolicy(context.TODO(), "pizza", "")
	assert.NoError(t, err)
	err = testutil.CollectAndCompare(collector, expectedMetrics(1, 0, 0, 0))
	assert.NoError(t, err)
}
