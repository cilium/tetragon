// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fsscan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/google/uuid"
)

var (
	// special error to inidicate that fileystem scanning found a file that
	// matches the container id, without, however, matching the pod id.
	ErrContainerPathWithoutMatchingPodID = errors.New("found cgroup file that matches the container id, but not the pod id")
)

// FsScanner is a utility for scanning the filesystem to find container cgroup directories.
type FsScanner interface {
	// FindContainer returns:
	//   path, nil: if the container cgroup was found
	//   path, ErrContainerPathWithoutMatchingPodID: if the container cgroup was found, but the pod id did not match the parent directory
	//   "", err: if the container cgroup was not found.
	//
	// NB: FindContainerPath returns ErrContainerPathWithoutMatchingPodID only if the directory
	// matching the pod id did not existed in the fs.
	//
	// Callers need to serialize concurrent access to this function on their own.
	FindContainerPath(podID uuid.UUID, containerID string) (string, error)
}

func New() FsScanner {
	return &fsScannerState{}
}

type fsScannerState struct {
	knownPodDirs []string
	root         string
	rootErr      error
}

// We 've seen some cases, where the container cgroup file is not in a
// directory that mathces the pod id. To handle these cases, do a full scan of
// the root to find a directory with the container id.
func fsFullContainerScan(root string, containerID string) string {
	found := errors.New("Found")
	retPath := ""
	// NB: there might be more efficient ways of searching the file-system than WalkDir, but
	// use that for now and we can improve later as needed.
	filepath.WalkDir(root, func(path string, dentry fs.DirEntry, err error) error {
		if err != nil || !dentry.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.Contains(base, containerID) {
			retPath = path
			return found
		}
		return nil
	})
	return retPath
}

// FindContainer implements FindContainer method from FsScanner
func (fs *fsScannerState) FindContainerPath(podID uuid.UUID, containerID string) (string, error) {

	// first, check the known (cached) locations
	for _, loc := range fs.knownPodDirs {
		podDir, containerDir := findPodAndContainerDirectory(loc, podID, containerID)
		if podDir == "" {
			continue
		}

		if containerDir != "" {
			return filepath.Join(podDir, containerDir), nil
		}

		// found the pod dir, but not the container dir. Return an error
		return "", fmt.Errorf("found pod dir=%s but failed to find container for id=%s", podDir, containerID)
	}

	if fs.root == "" && fs.rootErr == nil {
		fs.root, fs.rootErr = cgroups.HostCgroupRoot()
		if fs.rootErr != nil {
			logger.GetLogger().WithError(fs.rootErr).Warnf("failed to retrieve host cgroup root")
		}
	}
	if fs.rootErr != nil {
		return "", errors.New("no cgroup root")
	}

	podPath := fsFindPodPath(fs.root, podID)
	if podPath == "" {
		contPath := fsFullContainerScan(fs.root, containerID)
		if contPath == "" {
			return "", fmt.Errorf("no directory found that matches container-id '%s'", containerID)
		}
		return contPath, ErrContainerPathWithoutMatchingPodID
	}
	podDir := filepath.Dir(podPath)
	// found a new pod directory, added it to the cached locations
	fs.knownPodDirs = append(fs.knownPodDirs, podDir)
	logger.GetLogger().Infof("adding %s to cgroup pod directories", podDir)
	containerDir := findContainerDirectory(podPath, containerID)
	if containerDir == "" {
		return "", fmt.Errorf("found pod dir=%s but failed to find container for id=%s", podPath, containerID)
	}
	return filepath.Join(podPath, containerDir), nil
}

func podDirMatcher(podID uuid.UUID) func(p string) bool {
	s1 := podID.String()
	// replace '-' with '_' in "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	s2 := strings.Replace(s1, "-", "_", 4)
	return func(p string) bool {
		if strings.Contains(p, s1) {
			return true
		}
		if strings.Contains(p, s2) {
			return true
		}
		return false
	}
}

func findPodAndContainerDirectory(poddir string, podID uuid.UUID, containerID string) (string, string) {
	podpath := findPodDirectory(poddir, podID)
	if podpath == "" {
		return "", ""
	}
	podpath = filepath.Join(poddir, podpath)
	contpath := findContainerDirectory(podpath, containerID)
	return podpath, contpath
}

func findContainerDirectory(podpath string, containerID string) string {
	entries, err := os.ReadDir(podpath)
	if err != nil {
		return ""
	}
	for _, dentry := range entries {
		if !dentry.IsDir() {
			continue
		}

		name := dentry.Name()
		// skip crio's conmon container
		if strings.Contains(name, "crio-conmon") {
			continue
		}
		if strings.Contains(name, containerID) {
			return name
		}
	}

	return ""
}

func findPodDirectory(poddir string, podID uuid.UUID) string {
	podMatcher := podDirMatcher(podID)
	entries, err := os.ReadDir(poddir)
	if err != nil {
		return ""
	}
	for _, dentry := range entries {
		if !dentry.IsDir() {
			continue
		}

		name := dentry.Name()
		if podMatcher(name) {
			return name
		}
	}

	return ""
}

func fsFindPodPath(root string, podID uuid.UUID) string {
	found := errors.New("Found")
	podMatcher := podDirMatcher(podID)
	retPath := ""
	// NB: there might be more efficient ways of searching the file-system than WalkDir, but
	// use that for now and we can improve later as needed.
	filepath.WalkDir(root, func(path string, dentry fs.DirEntry, err error) error {
		if err != nil || !dentry.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if podMatcher(base) {
			retPath = path
			return found
		}
		return nil
	})
	return retPath
}
