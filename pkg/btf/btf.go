// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"fmt"
	"os"
	"path"

	"github.com/cilium/ebpf/btf"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"

	"golang.org/x/sys/unix"
)

var (
	btfFile string
)

func btfFileExists(file string) error {
	_, err := os.Stat(file)
	return err
}

func observerFindBTF(lib, btf string) (string, error) {
	if btf == "" {
		// Alternative to auto-discovery and/or command line argument we
		// can also set via environment variable.
		tetragonBtfEnv := os.Getenv("TETRAGON_BTF")
		if tetragonBtfEnv != "" {
			if _, err := os.Stat(tetragonBtfEnv); err != nil {
				return btf, err
			}
			return tetragonBtfEnv, nil
		}

		var kernelVersion string

		// Force configured kernel version
		if option.Config.KernelVersion != "" {
			kernelVersion = option.Config.KernelVersion
		} else {
			var uname unix.Utsname
			err := unix.Uname(&uname)
			if err != nil {
				return btf, fmt.Errorf("Kernel version lookup (uname -r) failing. Use '--kernel' to set manually: %w", err)
			}
			kernelVersion = unix.ByteSliceToString(uname.Release[:])
		}

		// Preference of BTF files, first search for kernel exposed BTF, then
		// check for vmlinux- hubble metadata, and finally if all those are missing
		// search the lib directory for a btf file.
		if _, err := os.Stat(defaults.DefaultBTFFile); err == nil {
			logger.GetLogger().WithField("btf-file", defaults.DefaultBTFFile).Info("BTF discovery: default kernel btf file found")
			return defaults.DefaultBTFFile, nil
		}
		logger.GetLogger().WithField("btf-file", defaults.DefaultBTFFile).Info("BTF discovery: default kernel btf file does not exist")

		runFile := path.Join(lib, "metadata", "vmlinux-"+kernelVersion)
		if _, err := os.Stat(runFile); err == nil {
			logger.GetLogger().WithField("btf-file", runFile).Info("BTF discovery: candidate btf file found")
			return runFile, nil
		}
		logger.GetLogger().WithField("btf-file", runFile).Info("BTF discovery: candidate btf file does not exist")

		runFile = path.Join(lib, "btf")
		if _, err := os.Stat(runFile); err == nil {
			logger.GetLogger().WithField("btf-file", runFile).Info("BTF discovery: candidate btf file found")
			return runFile, nil
		}
		logger.GetLogger().WithField("btf-file", runFile).Info("BTF discovery: candidate btf file does not exist")

		return btf, fmt.Errorf("Kernel version %q BTF search failed kernel is not included in supported list. Please check Tetragon requirements documentation, then use --btf option to specify BTF path and/or '--kernel' to specify kernel version", kernelVersion)
	}
	if err := btfFileExists(btf); err != nil {
		return btf, fmt.Errorf("User specified BTF does not exist: %w", err)
	}
	logger.GetLogger().WithField("btf-file", btf).Info("BTF file: user specified btf file found")
	return btf, nil
}

func NewBTF() (*btf.Spec, error) {
	return btf.LoadSpec(btfFile)
}

func InitCachedBTF(lib, btf string) error {
	var err error

	// Find BTF metdaata and populate btf opaqu object
	btfFile, err = observerFindBTF(lib, btf)
	if err != nil {
		return fmt.Errorf("tetragon, aborting kernel autodiscovery failed: %w", err)
	}
	return err
}

func GetCachedBTFFile() string {
	return btfFile
}

func FindNextBTFType(
	btfArgs *[api.MaxBtfArgDepth]api.ConfigBtfArg,
	currentType btf.Type,
	pathToFound *[]string,
	i int,
) (*btf.Type, error) {
	switch t := currentType.(type) {
	case *btf.Struct:
		memberWasFound := false
		for _, member := range t.Members {
			if member.Name == (*pathToFound)[i] {
				memberWasFound = true
				childOff := member.Offset.Bytes()
				if childOff > 255 {
					return nil, fmt.Errorf("Unable to reach type %v at offset %d", currentType.TypeName(), childOff)
				}
				(*btfArgs)[i].Offset = uint8(childOff)
				isNotLastChild := i < len(*pathToFound)-1 && i < api.MaxBtfArgDepth
				if isNotLastChild {
					return FindNextBTFType(btfArgs, member.Type, pathToFound, i+1)
				}
				currentType = member.Type
			}
		}
		if !memberWasFound {
			return nil, fmt.Errorf("Field '%s' not found in structure '%s'", (*pathToFound)[i], currentType.TypeName())
		}
	case *btf.Pointer:
		(*btfArgs)[i].IsPointer = uint8(1)
		return FindNextBTFType(btfArgs, t.Target, pathToFound, i)
	default:
		return nil, fmt.Errorf("Unexpected type %v in field %s", currentType.TypeName(), (*pathToFound)[i])
	}
	return &currentType, nil
}
