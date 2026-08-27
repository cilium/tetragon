// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/kernels"
)

func extractKernelVersion(fileName string) string {
	if idx := strings.LastIndex(fileName, "_v"); idx != -1 {
		versionPart := strings.TrimSuffix(fileName[idx+2:], ".o")
		if len(versionPart) >= 2 {
			if versionPart[:1] == "1" {
				panic("version 10.x not supported (we will need to disambiguate notation): " + versionPart)
			}
			return versionPart[:1] + "." + versionPart[1:]
		}
	}

	return ""
}

func extractBaseName(fileName string) string {
	if idx := strings.LastIndex(fileName, "_v"); idx != -1 {
		return fileName[:idx]
	}
	return strings.TrimSuffix(fileName, ".o")
}

type FileSelection struct {
	SelectedFile string
	SkippedFiles []string
}

func selectKernelVersionFiles(fileNames []string, currentKernelStr string) (map[string]FileSelection, error) {
	if currentKernelStr == "" {
		return nil, errors.New("no kernel version provided")
	}

	currentKernelVer := kernels.KernelStringToNumeric(currentKernelStr)

	type fileVersion struct {
		fileName string
		version  string
	}

	fileGroups := make(map[string][]fileVersion)

	for _, fileName := range fileNames {
		if filepath.Ext(fileName) != ".o" {
			continue
		}

		baseName := extractBaseName(fileName)
		version := extractKernelVersion(fileName)

		fileGroups[baseName] = append(fileGroups[baseName], fileVersion{
			fileName: fileName,
			version:  version,
		})
	}

	selections := make(map[string]FileSelection)

	for baseName, versions := range fileGroups {
		if len(versions) == 1 {
			selections[baseName] = FileSelection{
				SelectedFile: versions[0].fileName,
				SkippedFiles: nil,
			}
			continue
		}

		var bestMatch fileVersion
		var bestVersion string
		found := false

		for _, v := range versions {
			if v.version == "" {
				if !found {
					bestMatch = v
					bestVersion = ""
					found = true
				}
				continue
			}

			requiredVer := kernels.KernelStringToNumeric(v.version)
			if requiredVer > currentKernelVer {
				continue
			}

			if !found {
				bestMatch = v
				bestVersion = v.version
				found = true
			} else if bestVersion == "" || v.version > bestVersion {
				bestMatch = v
				bestVersion = v.version
			}
		}

		if found {
			var skipped []string
			for _, v := range versions {
				if v.fileName != bestMatch.fileName && v.version != "" {
					skipped = append(skipped, v.fileName)
				}
			}
			selections[baseName] = FileSelection{
				SelectedFile: bestMatch.fileName,
				SkippedFiles: skipped,
			}
		}
	}

	return selections, nil
}

func selectKernelVersionFilesForTest(t *testing.T, files []os.DirEntry) map[string]bool {
	t.Helper()
	_, currentKernelStr, err := kernels.GetKernelVersion("", "/proc")
	if err != nil {
		t.Logf("Warning: could not get kernel version, will test all files: %v", err)
		return nil
	}

	fileNames := make([]string, 0, len(files))
	for _, file := range files {
		if !file.IsDir() {
			fileNames = append(fileNames, file.Name())
		}
	}

	result, err := selectKernelVersionFiles(fileNames, currentKernelStr)
	if err != nil {
		t.Logf("Warning: %v, will test all files", err)
		return nil
	}

	for _, selection := range result {
		for _, skippedFile := range selection.SkippedFiles {
			t.Logf("%s ⊘ (using %s for kernel %s)", skippedFile, selection.SelectedFile, currentKernelStr)
		}
	}

	selected := make(map[string]bool)
	for _, selection := range result {
		selected[selection.SelectedFile] = true
	}

	return selected
}
