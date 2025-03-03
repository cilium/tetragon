// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tester

// revive:disable:context-as-argument

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	cgt "github.com/cilium/tetragon/pkg/testutils/cgroup"
	testprogs "github.com/cilium/tetragon/pkg/testutils/progs"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	cgfsRoot = "/sys/fs/cgroup"
	envVar   = "policyfilterTester"
)

type Tester struct {
	SensorMgr  *sensors.Manager
	Pfstate    policyfilter.State
	ProgTester *testprogs.Tester
	CgPath     string
	CgID       uint64
}

func Start(t *testing.T, ctx context.Context) *Tester {
	// capture tetragon log in the t
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

	// initialize things
	policyfilter.TestingEnableAndReset(t)
	err := observer.InitDataCache(1024)
	require.NoError(t, err)
	// NB: this is needed so that we can properly configure cgroupv2
	err = confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	require.NoError(t, err)

	// initialize base and test sensor
	// NB: using ret.SensorMgr to load these sensors does not seem to work as expected
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())

	// start sensor manager (and policyfilter)
	ret := &Tester{}
	ret.Pfstate, err = policyfilter.GetState()
	require.NoError(t, err)
	ret.SensorMgr, err = sensors.StartSensorManagerWithPF(bpf.MapPrefixPath(), ret.Pfstate)
	require.NoError(t, err)

	// create a cgroup path
	ret.CgPath = cgt.CgfsMkTemp(t, cgfsRoot, fmt.Sprintf("test-%s-*", t.Name()))
	ret.CgID, err = cgroups.GetCgroupIdFromPath(ret.CgPath)
	require.NoError(t, err)
	t.Logf("cgroup path:%s id:%d", ret.CgPath, ret.CgID)

	// create a progTester and add it to the cgroup
	ret.ProgTester = testprogs.StartTester(t, ctx)
	ret.ProgTester.AddToCgroup(t, ret.CgPath)
	t.Cleanup(func() {
		// stop progTester. We need to do this here, so that the Cleanup() of CgfsMkTemp
		// that removes the cgroup test will succeed.
		ret.ProgTester.Stop()
	})
	if false {
		out, err := ret.ProgTester.Command("exec /usr/bin/cat /proc/self/cgroup")
		require.NoError(t, err, out)
		t.Logf("progtester cgroup: %s", out)
	}

	return ret
}

func (pft *Tester) AddPolicy(t *testing.T, ctx context.Context, tp *tracingpolicy.GenericTracingPolicyNamespaced) {
	err := pft.SensorMgr.AddTracingPolicy(ctx, tp)
	require.NoError(t, err)
	err = pft.Pfstate.AddPodContainer(
		policyfilter.PodID(uuid.New()),
		tracingpolicy.Namespace(tp), "workload", "kind", nil,
		"pod-container", policyfilter.CgroupID(pft.CgID), "container-name")
	require.NoError(t, err)

	// NB: make true if you want to see a dump of the policyfilter maps
	if false {
		fname := filepath.Join(bpf.MapPrefixPath(), policyfilter.MapName)
		pfMap, err := policyfilter.OpenMap(fname)
		require.NoError(t, err)
		pfData, err := pfMap.Dump()
		require.NoError(t, err)
		t.Logf("pfMap(%s):\n%+v\n", fname, pfData)
	}

	t.Cleanup(func() {
		pft.SensorMgr.DeleteTracingPolicy(ctx, tp.TpName(), tracingpolicy.Namespace(tp))
	})
}
