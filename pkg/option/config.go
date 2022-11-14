// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/logger"
)

type config struct {
	Debug           bool
	ProcFS          string
	KernelVersion   string
	HubbleLib       string
	BTF             string
	Verbosity       int
	ForceSmallProgs bool

	EnableCilium      bool
	EnableProcessNs   bool
	EnableProcessCred bool
	EnableK8s         bool

	DisableKprobeMulti bool

	GopsAddr string

	CiliumDir string
	MapDir    string
	BpfDir    string

	LogOpts map[string]string

	RBSize      int
	RBSizeTotal int

	EventQueueSize uint

	ReleasePinned bool
}

var (
	log = logger.GetLogger()

	// Config contains all the configuration used by Tetragon.
	Config = config{
		// Initialize global defaults below.

		// ProcFS defaults to /proc.
		ProcFS: "/proc",

		// LogOpts contains logger parameters
		LogOpts: make(map[string]string),
	}
)

// ReadDirConfig reads the given directory and returns a map that maps the
// filename to the contents of that file.
func ReadDirConfig(dirName string) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	files, err := os.ReadDir(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %s", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fName := filepath.Join(dirName, f.Name())

		// the file can still be a symlink to a directory
		if f.Type()&os.ModeSymlink == 0 {
			absFileName, err := filepath.EvalSymlinks(fName)
			if err != nil {
				log.WithError(err).Warnf("Unable to read configuration file %q", absFileName)
				continue
			}
			fName = absFileName
		}

		fi, err := os.Stat(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		if fi.Mode().IsDir() {
			continue
		}

		b, err := os.ReadFile(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		m[f.Name()] = string(bytes.TrimSpace(b))
	}
	return m, nil
}
