// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package vmrunner

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/cilium/little-vm-helper/pkg/slogger"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

// the tester programs live here in the VM
const testerProgsVMDir = "/usr/local/lib/tetragon/tester-progs"

var errNoInstallScript = errors.New("could not find install.sh")

// buildImage builds the VM image with tetragon and the tester programs. With
// a selection, it also enables the unit that runs it at boot.
func buildImage(log slogger.Logger, conf *Conf, tmpDir string, sel *policytest.Selection) error {
	fsActions, err := lvh.FilesystemActions(conf.Filesystems, tmpDir)
	if err != nil {
		return err
	}

	netActions, err := lvh.NetActions(tmpDir)
	if err != nil {
		return err
	}

	tetragonActions, err := tetragonActions(conf, tmpDir, sel)
	if err != nil {
		return err
	}

	actions := lvh.BaseActions(&conf.Conf)
	actions = append(actions, tetragonActions...)
	actions = append(actions, fsActions...)
	actions = append(actions, netActions...)

	return lvh.BuildImage(log, &conf.Conf, actions, true)
}

// tetragonActions installs tetragon and the tester programs in the image.
// With a selection, it also enables the unit that runs it at boot.
func tetragonActions(conf *Conf, tmpDir string, sel *policytest.Selection) ([]images.Action, error) {
	ret := make([]images.Action, 0)

	// copy BTF file to the VM
	vmBTFFile := ""
	if conf.BTFFile != "" {
		act, path, err := lvh.BTFAction(conf.BTFFile)
		if err != nil {
			return nil, err
		}
		ret = append(ret, act)
		vmBTFFile = path
	}

	if conf.TetragonInstallDir != "" {
		additionalArgs := ""
		if conf.BTFFile != "" {
			additionalArgs = "--btf " + vmBTFFile
		}
		service, err := lvh.TetragonServiceFile(filepath.Join(tmpDir, lvh.TetragonService), additionalArgs)
		if err != nil {
			return nil, err
		}
		ret = append(ret,
			// install.sh
			images.Action{Op: &images.CopyInCommand{
				LocalPath: filepath.Join(conf.TetragonInstallDir, "usr", "local"),
				RemoteDir: "/usr",
			}},
			// tetragon systemd service
			images.Action{Op: &images.CopyInCommand{
				LocalPath: service,
				RemoteDir: "/etc/systemd/system/",
			}},
			images.Action{Op: &images.RunCommand{Cmd: "systemctl enable " + lvh.TetragonService}},
		)
	} else {
		tarball, err := uncompressed(conf.TetragonTarball, tmpDir)
		if err != nil {
			return nil, err
		}

		tetragonInstallSh, err := tarballInstallPath(tarball)
		if err != nil {
			return nil, err
		}
		remoteDir := "/tmp"
		ret = append(ret,
			images.Action{Op: &images.TarInCommand{
				TarFile:   tarball,
				RemoteDir: remoteDir,
			}},
			images.Action{Op: &images.RunCommand{Cmd: filepath.Join(remoteDir, tetragonInstallSh)}},
			images.Action{Op: &images.AppendLineCommand{
				File: "/etc/tetragon/tetragon.conf.d/btf",
				Line: vmBTFFile,
			}},
		)
	}

	// install tester progs
	if conf.TesterProgsDir != "" {
		act, err := copyTesterProgsAction(conf.TesterProgsDir, tmpDir)
		if err != nil {
			return nil, err
		}
		ret = append(ret, act)
	} else {
		tarball, err := uncompressed(conf.TesterProgsTarball, tmpDir)
		if err != nil {
			return nil, err
		}
		ret = append(ret,
			images.Action{Op: &images.TarInCommand{
				TarFile:   tarball,
				RemoteDir: filepath.Dir(testerProgsVMDir),
			}})
	}

	if sel != nil {
		// tetragon policytester systemd service
		names := slices.Sorted(maps.Keys(conf.Environment))
		environment := make([]string, 0, len(names))
		for _, name := range names {
			// systemd expands % specifiers in Environment= too
			environment = append(environment, strings.ReplaceAll(strconv.Quote(name+"="+conf.Environment[name]), "%", "%%"))
		}
		ptArgs, err := conf.policytestArgs(sel)
		if err != nil {
			return nil, err
		}
		service, err := policytesterServiceFile(filepath.Join(tmpDir, policytesterService), ptArgs, strings.Join(environment, " "))
		if err != nil {
			return nil, err
		}
		ret = append(ret,
			images.Action{Op: &images.CopyInCommand{
				LocalPath: service,
				RemoteDir: "/etc/systemd/system/",
			}},
			images.Action{Op: &images.RunCommand{
				Cmd: "systemctl enable " + policytesterService,
			}})
	}

	return ret, nil
}

// copyTesterProgsAction copies the tester programs of hostDir into the image.
func copyTesterProgsAction(hostDir string, tmpDir string) (images.Action, error) {
	// NB: because in general, the basename of hostDir is not the same as the basename of
	// testerProgsVMDir, we copy the binaries in the temp directory, and do the action from there.
	dstDir := filepath.Join(tmpDir, filepath.Base(testerProgsVMDir))
	if err := os.Mkdir(dstDir, 0755); err != nil {
		return images.Action{}, err
	}

	if err := os.CopyFS(dstDir, os.DirFS(hostDir)); err != nil {
		return images.Action{}, fmt.Errorf("failed to copy the tester programs: %w", err)
	}

	return images.Action{Op: &images.CopyInCommand{
		LocalPath: dstDir,
		RemoteDir: filepath.Dir(testerProgsVMDir),
	}}, nil
}

// uncompressed returns a plain tar for a gzip-compressed tarball, and the
// tarball itself otherwise.
func uncompressed(tarball, tmpDir string) (string, error) {
	if strings.HasSuffix(tarball, ".gz") || strings.HasSuffix(tarball, ".tgz") {
		return decompressToTemp(tarball, tmpDir)
	}
	return tarball, nil
}

func tarballInstallPath(tarball string) (string, error) {
	f, err := os.Open(tarball)
	if err != nil {
		return "", err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", errNoInstallScript
		}
		if err != nil {
			return "", err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if path.Base(hdr.Name) == "install.sh" {
			return hdr.Name, nil
		}
	}
}

func decompressToTemp(fname, tmpDir string) (string, error) {
	in, err := os.Open(fname)
	if err != nil {
		return "", err
	}
	defer in.Close()

	gz, err := gzip.NewReader(in)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tmp, err := os.CreateTemp(tmpDir, "tetragon-*.tar")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmp, gz); err != nil {
		tmp.Close()
		os.Remove(tmp.Name()) // clean up on failure
		return "", err
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}

	return tmp.Name(), nil
}
