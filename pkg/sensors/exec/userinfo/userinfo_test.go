// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package userinfo

import (
	"testing"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/stretchr/testify/require"
)

func TestAccountUnix(t *testing.T) {
	hostNs, err := namespace.InitHostNamespace()
	require.NoError(t, err)

	ns := processapi.MsgNamespaces{}
	name, err := getAccountUnix(0, &ns)
	require.Equal(t, ErrNotInHostNs, err)
	require.Empty(t, name)

	ns = processapi.MsgNamespaces{
		UserInum: hostNs.User.Inum,
		MntInum:  hostNs.Mnt.Inum,
	}

	name, err = getAccountUnix(0, &ns)
	require.NoError(t, err)
	require.Equal(t, name, "root")

	ns.MntInum += 0x1000
	name, err = getAccountUnix(1, &ns)
	require.Equal(t, ErrNotInHostNs, err)
	require.Empty(t, name)
}
