// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPolicyID(name string) PolicyID {
	return PolicyID{
		Domain:    "grpc",
		Namespace: "test-namespace",
		Name:      name,
	}
}

func testPolicyState(name string) PolicyWithState {
	return PolicyWithState{
		YAML:    "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: " + name + "\n",
		Enabled: true,
	}
}

func TestOpenCreatesEmptyStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policies")

	store, err := OpenAndLoad(dir)
	require.NoError(t, err)
	assert.Empty(t, store.List())

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestPutReplacesRecord(t *testing.T) {
	store, err := OpenAndLoad(t.TempDir())
	require.NoError(t, err)

	id := testPolicyID("policy")
	pol := testPolicyState("policy")
	require.NoError(t, store.Put(id, pol))

	pol.Enabled = false
	pol.YAML += "spec: {}\n"
	require.NoError(t, store.Put(id, pol))

	assert.Equal(t, []PolicyEntry{{ID: id, Pol: pol}}, store.List())
	reopened, err := OpenAndLoad(store.dir)
	require.NoError(t, err)
	assert.Equal(t, []PolicyEntry{{ID: id, Pol: pol}}, reopened.List())
}

func TestPolicyWithoutNamespace(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenAndLoad(dir)
	require.NoError(t, err)

	id := testPolicyID("cluster-wide-policy")
	id.Namespace = ""
	state := testPolicyState("cluster-wide-policy")
	require.NoError(t, store.Put(id, state))

	reopened, err := OpenAndLoad(dir)
	require.NoError(t, err)
	got, ok := reopened.Get(id)
	require.True(t, ok)
	assert.Equal(t, state, got)
}

func TestDelete(t *testing.T) {
	store, err := OpenAndLoad(t.TempDir())
	require.NoError(t, err)

	id := testPolicyID("policy")
	state := testPolicyState("policy")
	require.NoError(t, store.Put(id, state))
	require.NoError(t, store.Delete(id))
	require.NoError(t, store.Delete(id))

	_, ok := store.Get(id)
	assert.False(t, ok)

	reopened, err := OpenAndLoad(store.dir)
	require.NoError(t, err)
	assert.Empty(t, reopened.List())
}

func TestOpenRejectsInvalidRecords(t *testing.T) {
	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "invalid.json"), []byte("{"), recordFileMode))

		_, err := OpenAndLoad(dir)
		require.ErrorContains(t, err, "decode policy record")
	})

	t.Run("unexpected filename", func(t *testing.T) {
		dir := t.TempDir()
		state := testPolicyState("policy")
		data, err := json.Marshal(state)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "wrong.json"), data, recordFileMode))

		_, err = OpenAndLoad(dir)
		require.ErrorContains(t, err, "unexpected filename")
	})
}

func TestOpenIgnoresTemporaryAndUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".record.json.tmp-123"), []byte("{"), recordFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README"), []byte("unrelated"), recordFileMode))

	store, err := OpenAndLoad(dir)
	require.NoError(t, err)
	assert.Empty(t, store.List())
}

func TestOpenRejectsFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store")
	require.NoError(t, os.WriteFile(path, nil, recordFileMode))

	_, err := OpenAndLoad(path)
	require.Error(t, err)
}

func TestConcurrentAccess(t *testing.T) {
	store, err := OpenAndLoad(t.TempDir())
	require.NoError(t, err)

	const count = 20
	var wg sync.WaitGroup
	errCh := make(chan error, count)
	for i := range count {
		wg.Go(func() {
			id := testPolicyID(fmt.Sprintf("policy-%02d", i))
			state := testPolicyState(fmt.Sprintf("policy-%02d", i))
			if err := store.Put(id, state); err != nil {
				errCh <- err
				return
			}
			_, ok := store.Get(id)
			if !ok {
				errCh <- fmt.Errorf("record %q was not found", id.Name)
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	assert.Len(t, store.List(), count)
}
