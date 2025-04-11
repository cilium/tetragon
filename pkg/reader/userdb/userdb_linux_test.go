// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package userdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsersRecords(t *testing.T) {
	name, err := UsersCache.lookupUser(0)
	assert.Error(t, err)
	assert.Empty(t, name)

	UsersCache.addUser(0, "root")
	name, err = UsersCache.lookupUser(0)
	assert.NoError(t, err)
	assert.Equal(t, "root", name)

	name, err = UsersCache.LookupUser(2)
	assert.NoError(t, err)
	name2, err := UsersCache.lookupUser(2)
	assert.NoError(t, err)
	assert.Equal(t, name, name2)
}
