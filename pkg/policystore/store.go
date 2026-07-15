// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

const (
	recordFileSuffix     = ".json"
	recordTempFileSuffix = ".json.tmp"
	recordDirMode        = 0o700
	recordFileMode       = 0o600
)

var errDstRemoved = errors.New("destination removed")

type Store struct {
	dir     string
	mu      sync.Mutex
	records map[PolicyID]PolicyWithState
}

// gets aaa:bbb:ccc.json and returns (aaa, bbb, ccc)
func decodeFilename(name string) (string, string, string, error) {
	base := strings.TrimSuffix(name, recordFileSuffix)
	parts := strings.SplitN(base, ":", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid filename %s: expected format aaa:bbb:ccc.json", name)
	}

	return parts[0], parts[1], parts[2], nil
}

func OpenAndLoad(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("policy store directory must not be empty")
	}

	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, recordDirMode); err != nil {
		return nil, fmt.Errorf("create policy store directory %s: %w", dir, err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat policy store directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("policy store path %s is not a directory", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy store directory %s: %w", dir, err)
	}

	s := &Store{
		dir:     dir,
		records: make(map[PolicyID]PolicyWithState),
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, recordTempFileSuffix) || !strings.HasSuffix(name, recordFileSuffix) {
			logger.GetLogger().Warn("unrecognized file in policy store",
				"filename", name)
			continue
		}

		info, err := entry.Info()
		if err != nil {
			logger.GetLogger().Warn("stat policy record failed",
				logfields.Error, err,
				"path", filepath.Join(dir, name))
			continue
		}
		if !info.Mode().IsRegular() {
			logger.GetLogger().Warn("policy record is not a regular file",
				"path", filepath.Join(dir, name))
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy record %s: %w", path, err)
		}

		var pol PolicyWithState
		if err := json.Unmarshal(data, &pol); err != nil {
			return nil, fmt.Errorf("decode policy record %s: %w", path, err)
		}

		polName, polNamespae, polDomain, polErr := decodeFilename(name)
		if polErr != nil {
			return nil, fmt.Errorf("policy record %s has unexpected filename", path)
		}
		id := PolicyID{
			Name:      polName,
			Namespace: polNamespae,
			Domain:    polDomain,
		}
		if _, exists := s.records[id]; exists {
			return nil, fmt.Errorf("duplicate policy record for %s", id)
		}

		s.records[id] = pol
	}

	return s, nil
}

func (s *Store) List() []PolicyEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := make([]PolicyEntry, 0, len(s.records))
	for id, pol := range s.records {
		entries = append(entries, PolicyEntry{ID: id, Pol: pol})
	}
	return entries
}

func (s *Store) Get(id PolicyID) (PolicyWithState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.records[id]
	return state, ok
}

func (s *Store) Put(id PolicyID, state PolicyWithState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode policy record for %s: %w", id, err)
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := writeAtomic(s.dir, id.String(), data); err != nil {
		if errors.Is(err, errDstRemoved) {
			delete(s.records, id)
		}
		return fmt.Errorf("write policy record for %s: %w", id, err)
	}
	s.records[id] = state
	return nil
}

func (s *Store) Delete(id PolicyID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, id.String()+recordFileSuffix)
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete policy record for %s: %w", id, err)
	}

	delete(s.records, id)
	if err == nil {
		if err := syncDir(s.dir); err != nil {
			return fmt.Errorf("sync policy store after deleting %s: %w", id, err)
		}
	}
	return nil
}

func chmodWriteSync(f *os.File, data []byte) error {
	defer f.Close()
	if err := f.Chmod(recordFileMode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return nil
}

// writeAtomic attempts to write data atomicaly to a file
// if an error happens, the caller should try to put the previous
// record if anything exists
func writeAtomic(dir, name string, data []byte) (retErr error) {
	tmp, err := os.CreateTemp(dir, name+".*"+recordTempFileSuffix)
	if err != nil {
		retErr = fmt.Errorf("failed to create tempfile in dir %q for name %q: %w", dir, name, err)
		return
	}

	tmpName := tmp.Name()
	fileToRemove := tmpName
	defer func() {
		if retErr == nil {
			return
		}
		if err := os.Remove(fileToRemove); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to remove %q: %w", fileToRemove, err))
		} else {
			if tmpName != fileToRemove {
				retErr = errors.Join(retErr, errDstRemoved)
			}
		}
		// make an attempt to sync the dir
		syncDir(dir)
	}()

	if err := chmodWriteSync(tmp, data); err != nil {
		retErr = fmt.Errorf("failed to write data to tempfile %q: %w", tmpName, err)
		return
	}

	dst := filepath.Join(dir, name+recordFileSuffix)
	if err := os.Rename(tmpName, dst); err != nil {
		retErr = fmt.Errorf("failed rename tempfile %q to %q: %w", tmpName, dst, err)
		return
	}

	// now the proper file exists, we need to sync the directory to make this fully atomic in
	// the rare occasion that something bad happens, we remove the file
	fileToRemove = dst
	if err := syncDir(dir); err != nil {
		retErr = fmt.Errorf("failed to sync directory: %w", err)
		return
	}

	return
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
