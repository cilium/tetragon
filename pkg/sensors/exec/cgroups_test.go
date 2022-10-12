// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/base"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Test loading bpf cgroups programs
func TestLoadCgroupsPrograms(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5
	tus.LoadSensor(ctx, t, base.GetInitialSensor())
	tus.LoadSensor(ctx, t, testsensor.GetTestSensor())
	tus.LoadSensor(ctx, t, testsensor.GetCgroupSensor())
}

// Test `tg_conf_map` BPF map that it can hold runtime configuration
func TestTgRuntimeConf(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	_, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	val, err := testutils.GetTgRuntimeConf()
	assert.NoError(t, err)

	assert.NotZero(t, val.NSPID)
	assert.NotZero(t, val.TgCgrpId)
	assert.NotZero(t, val.Mode)
	assert.NotZero(t, val.CgrpFsMagic)

	mapDir := bpf.MapPrefixPath()
	err = testutils.UpdateTgRuntimeConf(mapDir, val)
	assert.NoError(t, err)

	ret, err := testutils.ReadTgRuntimeConf(mapDir)
	assert.NoError(t, err)

	assert.EqualValues(t, ret, val)
}
