// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestReadAndSetFlagsCgroupRate(t *testing.T) {
	originalConfig := Config
	viper.Reset()
	t.Cleanup(func() {
		Config = originalConfig
		viper.Reset()
	})
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	AddFlags(flags)
	require.NoError(t, viper.BindPFlags(flags))

	for _, rate := range []string{"10", "sure,1s", "1,nope", "-1,1s", "1,-1s"} {
		t.Run(rate, func(t *testing.T) {
			viper.Set(KeyCgroupRate, rate)
			require.ErrorContains(t, ReadAndSetFlags(), KeyCgroupRate)
		})
	}

	viper.Set(KeyCgroupRate, "1,1s")
	require.NoError(t, ReadAndSetFlags())
	require.Equal(t, CgroupRate{Events: 1, Interval: 1000000000}, Config.CgroupRate)

	viper.Set(KeyCgroupRate, "")
	require.NoError(t, ReadAndSetFlags())
	require.Equal(t, CgroupRate{}, Config.CgroupRate)
}
