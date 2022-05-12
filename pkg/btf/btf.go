// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"

	"golang.org/x/sys/unix"
)

var (
	/* opaque pointer to C BTF object */
	btfObj = bpf.BTFNil

	btfFile string
)

func btfFileExists(file string) error {
	_, err := os.Stat(file)
	return err
}

func observerFindBTF(ctx context.Context, lib, btf string) (string, error) {
	if btf == "" {
		var uname unix.Utsname

		// Alternative to auto-discovery and/or command line argument we
		// can also set via environment variable.
		fgsBtfEnv := os.Getenv("FGS_BTF")
		if fgsBtfEnv != "" {
			if _, err := os.Stat(fgsBtfEnv); err != nil {
				return btf, err
			}
			return fgsBtfEnv, nil
		}

		err := unix.Uname(&uname)
		if err != nil {
			return btf, fmt.Errorf("Kernel version lookup (uname -r) failing. Use '--kernel' to set manually: %w", err)
		}
		n := bytes.IndexByte(uname.Release[:], 0)

		// Preference of BTF files, first search for kernel exposed BTF, then
		// check for vmlinux- hubble metadata, and finally if all those are missing
		// search the lib directory for a btf file.
		runFile := path.Join("/sys", "kernel", "btf", "vmlinux")
		if _, err := os.Stat(runFile); err == nil {
			return runFile, nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join(lib, "metadata", "vmlinux-"+string(uname.Release[:n]))
		if _, err := os.Stat(runFile); err == nil {
			return runFile, nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join(lib, "btf")
		if _, err := os.Stat(runFile); err == nil {
			return runFile, nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		return btf, fmt.Errorf("Kernel version %q BTF search failed kernel is not included in supported list. Use --btf option to specify BTF path and/or '--kernel' to specify kernel version", uname.Release[:n])
	}
	if err := btfFileExists(btf); err != nil {
		return btf, fmt.Errorf("User specified BTF does not exist: %w", err)
	}
	return btf, nil
}

func NewBTF() (bpf.BTF, error) {
	return bpf.NewBTF(btfFile)
}

func InitCachedBTF(ctx context.Context, lib, btf string) error {
	var err error

	// Find BTF metdaata and populate btf opaqu object
	btfFile, err = observerFindBTF(ctx, lib, btf)
	if err != nil {
		return fmt.Errorf("hubble-fgs, aborting kernel autodiscovery failed: %w", err)
	}
	btfObj, err = NewBTF()
	return err
}

func GetCachedBTFFile() string {
	return btfFile
}

func GetCachedBTF() bpf.BTF {
	return btfObj
}

func FreeCachedBTF() {
	if btfObj != bpf.BTFNil {
		btfObj.Close()
		btfObj = bpf.BTFNil
	}
}
