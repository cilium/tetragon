// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

var (
	ConfigFname    = "kernels.json"
	KernelsDirName = "kernels"
)

type InitDirFlags struct {
	Force      bool
	BackupConf bool
}

// Initalizes a new directory for kernels (it will create it if it does not exist).
//
// the provided conf will be saved in the directory.
// if conf is nil, an empty configuration will be used.
func InitDir(log *logrus.Logger, dir string, conf *Conf, flags InitDirFlags) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create directory '%s': %w", dir, err)
	}

	confFname := path.Join(dir, ConfigFname)
	if !flags.Force {
		if _, err := os.Stat(confFname); err == nil {
			return fmt.Errorf("config file `%s` already exists", confFname)
		}
	}

	if conf == nil {
		conf = &Conf{
			Kernels:    make([]KernelConf, 0),
			CommonOpts: make([]ConfigOption, 0),
		}
	}

	return conf.SaveTo(log, dir, flags.BackupConf)
}

// Load configuration from a directory
func LoadDir(dir string) (*KernelsDir, error) {
	data, err := os.ReadFile(path.Join(dir, ConfigFname))
	if err != nil {
		return nil, err
	}

	kd := KernelsDir{Dir: filepath.Join(dir, KernelsDirName)}
	err = json.Unmarshal(data, &kd.Conf)
	if err != nil {
		return nil, err
	}
	return &kd, nil
}

type AddKernelFlags struct {
	BackupConf bool
	Fetch      bool
}

func AddKernel(ctx context.Context, log *logrus.Logger, dir string, cnf *KernelConf, flags AddKernelFlags) error {
	kd, err := LoadDir(dir)
	if err != nil {
		return err
	}

	if kd.KernelConfig(cnf.Name) != nil {
		return fmt.Errorf("kernel `%s` already exists", cnf.Name)
	}

	kd.Conf.Kernels = append(kd.Conf.Kernels, *cnf)
	if err := kd.Conf.SaveTo(log, dir, flags.BackupConf); err != nil {
		return err
	}

	if flags.Fetch {
		kURL, err := ParseURL(cnf.URL)
		if err != nil {
			return err
		}

		if err := kURL.fetch(ctx, log, kd.Dir, cnf.Name); err != nil {
			return err
		}
	}

	return nil
}

// RemoveKernel will remove a kernel.
// It will typically try to continue, even if it encounters an error
func RemoveKernel(ctx context.Context, log_ *logrus.Logger, dir string, name string, backupConf bool) error {
	kd, err := LoadDir(dir)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, name)
	log := log_.WithField("kernel", name).WithField("path", path)

	cnf := kd.RemoveKernelConfig(name)
	if cnf == nil {
		log.Warn("kernel does not exist, will try to remove path")
		if err := os.RemoveAll(path); err != nil {
			log.WithError(err).Warn("removing path failed")
			return fmt.Errorf("failed to remove kernel `%s`: %w", name, err)
		}
		return fmt.Errorf("kernel `%s` does not exist in configuration", name)
	}
	defer kd.Conf.SaveTo(log, dir, backupConf)

	if kurl, parseErr := ParseURL(cnf.URL); parseErr != nil {
		log.WithField("url", cnf.URL).Warn("kernel has invalid URL, will try to remove path")
		if err := os.RemoveAll(path); err != nil {
			log.WithError(err).Warn("removing path failed")
			return fmt.Errorf("failed to remove kernel `%s`: %w", name, err)
		}
		return fmt.Errorf("kernel `%s` has invalid URL `%s`", name, cnf.URL)
	} else {
		return kurl.remove(ctx, log, kd.Dir, name)
	}
}

func getKernelInfo(dir, kname string) (*KernelsDir, *KernelConf, KernelURL, error) {
	kd, err := LoadDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}

	kconf := kd.KernelConfig(kname)
	if kconf == nil {
		return nil, nil, nil, fmt.Errorf("kernel `%s` not found", kname)
	}

	kURL, err := ParseURL(kconf.URL)
	if err != nil {
		return nil, nil, nil, err
	}

	return kd, kconf, kURL, nil

}

func FetchKernel(ctx context.Context, log *logrus.Logger, dir, kname string) error {
	kd, kc, kurl, err := getKernelInfo(dir, kname)
	if err != nil {
		return err
	}

	return kurl.fetch(ctx, log, kd.Dir, kc.Name)
}

func BuildKernel(ctx context.Context, log *logrus.Logger, dir, kname string, fetch bool) error {
	kd, kc, kurl, err := getKernelInfo(dir, kname)
	if err != nil {
		return err
	}

	if fetch {
		if err := kurl.fetch(ctx, log, kd.Dir, kc.Name); err != nil {
			return fmt.Errorf("fetch failed: %w", err)
		}

	}

	return kd.buildKernel(ctx, log, kc)
}
