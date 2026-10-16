// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// go test -exec sudo ./pkg/sensors/tracing -run TestKprobeAllSelectorsNoRewriteConstants -v
func TestKprobeAllSelectorsNoRewriteConstants(t *testing.T) {
	if !config.EnableLargeProgs() {
		t.Skip("selector constants require large BPF programs")
	}

	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	require.NoError(t, observer.InitDataCache(1024))
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())

	filePath := filepath.Join(t.TempDir(), "test-file")
	require.NoError(t, os.WriteFile(filePath, nil, 0600))

	tp := &tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{Name: "kprobe-all-selectors"},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{{
				Call: "security_file_open",
				Args: []v1alpha1.KProbeArg{{Index: 0, Type: "file"}},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchPIDs: []v1alpha1.PIDSelector{{
						Operator: "In",
						Values:   []uint32{observertesthelper.GetMyPid()},
					}},
					MatchArgs: []v1alpha1.ArgSelector{{
						Index:    0,
						Operator: "Equal",
						Values:   []string{filePath},
					}},
				}},
			}},
		},
	}
	sens, err := sensors.SensorsFromPolicy(tp, policyfilter.NoFilterID)
	require.NoError(t, err)
	require.Len(t, sens, 1)
	sensor := sens[0].(*sensors.Sensor)
	require.Len(t, sensor.Progs, 1)
	load := sensor.Progs[0]
	require.Equal(t, "generic_kprobe", load.Type)
	load.RewriteConstants = nil // Do not override selector constants.
	tus.LoadSensor(t, sensor)
	require.Nil(t, load.RewriteConstants)

	var events int
	ops := func() {
		f, err := os.Open(filePath)
		if assert.NoError(t, err) {
			assert.NoError(t, f.Close())
		}
	}
	handler := func(ev notify.Message) error {
		if kp, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
			require.Equal(t, "security_file_open", kp.FuncName)
			require.Len(t, kp.Args, 1)
			require.Equal(t, filePath, kp.Args[0].(tracingapi.MsgGenericKprobeArgFile).Value)
			events++
		}
		return nil
	}
	perfring.RunTest(t, ctx, ops, handler)
	require.Equal(t, 1, events)
}
