// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestEnum(t *testing.T) {
	_, err := NewEnum([]string{"foo", "bar"}, "baz")
	require.Error(t, err)

	e, err := NewEnum([]string{"foo", "bar", "baz"}, "foo")
	require.NoError(t, err)

	require.Equal(t, "foo", e.Value)
	require.NoError(t, e.Set("bar"))
	require.Equal(t, "bar", e.Value)
	require.Error(t, e.Set("invalid"))
	require.Equal(t, "bar", e.Value)
}

func TestSliceEnum(t *testing.T) {
	_, err := NewSliceEnum([]string{"foo", "bar"}, []string{"baz", "bat"})
	require.Error(t, err)

	e, err := NewSliceEnum([]string{"foo", "bar", "baz"}, []string{"bar"})
	require.NoError(t, err)
	require.Len(t, e.Values, 1)
	require.Equal(t, "bar", e.Values[0])

	require.NoError(t, e.Set("baz"))
	require.Len(t, e.Values, 2)
	require.Equal(t, "bar", e.Values[0])
	require.Equal(t, "baz", e.Values[1])

	require.Error(t, e.Set("invalid"))
	require.Len(t, e.Values, 2)
}

func TestEnumPflag(t *testing.T) {
	currArgs := os.Args
	t.Cleanup(func() { os.Args = currArgs })

	os.Args = []string{"test", "--foo", "bar"}
	e, err := NewEnum([]string{"bar", "baz", "bat"}, "baz")
	require.NoError(t, err)
	cmd := cobra.Command{
		Use: "test",
		Run: func(_ *cobra.Command, _ []string) {
			require.Equal(t, "bar", e.Value)
		},
	}

	// Prepare enum-like flags
	flags := cmd.Flags()
	flags.Var(e, "foo", "test")
	require.NoError(t, cmd.Execute())
}
