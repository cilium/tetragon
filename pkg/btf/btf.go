// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package btf

import (
	"fmt"
	"os"
	"path"
	"reflect"

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

/*
FindNextBtfType function recursively search in a btf structure in order to
found a specific path until it reach the target or fail.

The function also search in embedded anonymous structures or unions to cover as
much use cases as possible. For instance, mm_struct have 2 fields, anonymous
struct and another type. But you are still able to look into the anonymous
struct by specifying a path like "mm.pgd.pgd".

@btfArgs: dest array for storing btf informations to reach the target on the
bpf side.
@currentType: The current type being proccessed, starts with root type.
@pathToFound: The string representation of the path to reach in the structures.
@i: The current depth, until last element of pathToFound.

Return: The last type found matching the path, or error.
*/
func FindNextBtfType(
	btfArgs *[api.MaxBtfArgDepth]api.ConfigBtfArg,
	currentType btf.Type,
	pathToFound []string,
	i int,
) (*btf.Type, error) {
	switch t := currentType.(type) {
	case *btf.Struct:
		return processMembers(btfArgs, currentType, t.Members, pathToFound, i)
	case *btf.Union:
		return processMembers(btfArgs, currentType, t.Members, pathToFound, i)
	case *btf.Pointer:
		(*btfArgs)[i-1].IsPointer = uint16(1)
		return FindNextBtfType(btfArgs, t.Target, pathToFound, i)
	case *btf.Typedef:
		return FindNextBtfType(btfArgs, t.Type, pathToFound, i)
	default:
		ty := currentType.TypeName()
		if len(ty) == 0 {
			ty = reflect.TypeOf(currentType).String()
		}
		return nil, fmt.Errorf("Unexpected type : %s has type %s", pathToFound[i-1], ty)
	}
}

func processMembers(
	btfArgs *[api.MaxBtfArgDepth]api.ConfigBtfArg,
	currentType btf.Type,
	members []btf.Member,
	pathToFound []string,
	i int,
) (*btf.Type, error) {
	var lastError error
	memberWasFound := false
	for _, member := range members {
		if len(member.Name) == 0 { // If anonymous struct, fallthrough
			(*btfArgs)[i].Offset = member.Offset.Bytes()
			(*btfArgs)[i].IsInitialized = uint16(1)
			lastTy, err := FindNextBtfType(btfArgs, member.Type, pathToFound, i)
			if err != nil {
				lastError = err
				continue
			}
			return lastTy, nil
		}
		if member.Name == pathToFound[i] {
			memberWasFound = true
			(*btfArgs)[i].Offset = member.Offset.Bytes()
			(*btfArgs)[i].IsInitialized = uint16(1)
			isNotLastChild := i < len(pathToFound)-1 && i < api.MaxBtfArgDepth
			if isNotLastChild {
				return FindNextBtfType(btfArgs, member.Type, pathToFound, i+1)
			}
			currentType = member.Type
		}
	}
	if !memberWasFound {
		if lastError != nil {
			return nil, lastError
		}
		return nil, fmt.Errorf(
			"Attribute '%s' not found in structure '%s' found %v",
			pathToFound[i],
			currentType.TypeName(),
			members,
		)
	}
	if t, ok := currentType.(*btf.Pointer); ok {
		(*btfArgs)[i].IsPointer = uint16(1)
		currentType = t.Target
	} else if _, ok := currentType.(*btf.Int); ok {
		(*btfArgs)[i].IsPointer = uint16(1)
	}
	return &currentType, nil
}
