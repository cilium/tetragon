// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportRateLimitParsing(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected int
	}{
		{name: "valid positive integer", input: "1000", expected: 1000},
		{name: "disabled (-1)", input: "-1", expected: -1},
		{name: "zero drops all events", input: "0", expected: 0},
		{name: "invalid format defaults to 0", input: "50000,1s", expected: 0},
		{name: "non-integer string defaults to 0", input: "fast", expected: 0},
		{name: "empty string defaults to 0", input: "", expected: 0},
	}

	// Register all flags so viper has defaults for every key ReadAndSetFlags reads.
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	AddFlags(flags)
	require.NoError(t, viper.BindPFlags(flags))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set(KeyExportRateLimit, tc.input)
			t.Cleanup(func() { viper.Set(KeyExportRateLimit, "-1") })

			err := ReadAndSetFlags()
			require.NoError(t, err)

			assert.Equal(t, tc.expected, Config.ExportRateLimit)
		})
	}
}
