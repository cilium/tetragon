// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package userdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsersRecords(t *testing.T) {
	name, err := UsersCache.lookupUser(0)
	require.Error(t, err)
	assert.Empty(t, name)

	UsersCache.addUser(0, "root")
	name, err = UsersCache.lookupUser(0)
	require.NoError(t, err)
	assert.Equal(t, "root", name)

	//ToDo: We need to convert a unix-style uid to a Windows style RID
	// and construct the whole SID with that RID before looking up.

}
