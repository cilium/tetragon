// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/cilium/little-vm-helper/pkg/logcmd"
	"github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"
)

type KernelsDir struct {
	Dir  string
	Conf Conf
}

func (kd *KernelsDir) KernelConfig(name string) *KernelConf {
	for i := range kd.Conf.Kernels {
		if kd.Conf.Kernels[i].Name == name {
			return &kd.Conf.Kernels[i]
		}
	}

	return nil
}

// RemoveKernelConfig returns the removed kernel config if it was found
func (kd *KernelsDir) RemoveKernelConfig(name string) *KernelConf {
	for i := range kd.Conf.Kernels {
		if kd.Conf.Kernels[i].Name == name {
			ret := &kd.Conf.Kernels[i]
			kd.Conf.Kernels = append(kd.Conf.Kernels[:i], kd.Conf.Kernels[i+1:]...)
			return ret
		}
	}

	return nil
}

func (kd *KernelsDir) ConfigureKernel(ctx context.Context, log *logrus.Logger, kernName string) error {
	kc := kd.KernelConfig(kernName)
	if kc == nil {
		return fmt.Errorf("kernel '%s' not found", kernName)
	}
	return kd.configureKernel(ctx, log, kc)
}

func kcfonfigValidate(opts []ConfigOption) error {

	var ret error
	// we want to check that:
	//  - what is supposed to be enabled, is enabled
	//  - what is supposed to be disabled, is not enabled

	type OptMapVal struct {
		enabled bool
		checked bool
	}

	optMap := make(map[string]OptMapVal)
	for _, opt := range opts {
		switch opt[0] {
		case "--enable":
			optMap[opt[1]] = OptMapVal{enabled: true}
		case "--disable":
			optMap[opt[1]] = OptMapVal{enabled: false}
		default:
			return fmt.Errorf("Unknown option: %s", opt[0])
		}
	}

	// validate config file
	kcfg, err := os.Open(".config")
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer kcfg.Close()

	enabledRe := regexp.MustCompile(`([a-zA-Z0-9_]+)=y`)
	disabledRe := regexp.MustCompile(`# ([a-zA-Z0-9_]+) is not set`)
	s := bufio.NewScanner(kcfg)
	for s.Scan() {
		txt := s.Text()
		var opt string
		optEnabled := false
		if match := enabledRe.FindStringSubmatch(txt); len(match) > 0 {
			opt = match[1]
			optEnabled = true
		} else if match := disabledRe.FindStringSubmatch(txt); len(match) > 0 {
			opt = match[1]
		} else {
			continue
		}

		mapVal, ok := optMap[opt]
		if !ok {
			continue
		}

		mapVal.checked = true
		optMap[opt] = mapVal

		if mapVal.enabled != optEnabled {
			err := fmt.Errorf("value %s misconfigured: expected: %t but seems to be %t based on '%s'", opt, mapVal.enabled, optEnabled, txt)
			ret = multierror.Append(ret, err)
		}

	}

	if err := s.Err(); err != nil {
		return err
	}

	for i, v := range optMap {
		if v.enabled && !v.checked {
			err := fmt.Errorf("value %s enabled but not found", i)
			ret = multierror.Append(ret, err)
		}
	}

	return ret
}

func (kd *KernelsDir) configureKernel(ctx context.Context, log *logrus.Logger, kc *KernelConf) error {
	srcDir := filepath.Join(kd.Dir, kc.Name)

	oldPath, err := os.Getwd()
	if err != nil {
		return err
	}
	err = os.Chdir(srcDir)
	if err != nil {
		return err
	}
	defer os.Chdir(oldPath)

	configOptions := kd.Conf.getOptions(kc)

	if err := logcmd.RunAndLogCommandContext(ctx, log, MakeBinary, "defconfig", "prepare"); err != nil {
		return err
	}

	configCmd := filepath.Join(".", "scripts", "config")
	for i, opts := range configOptions {
		// NB: we could do this in a single command, but doing it one-by-one makes it easier to debug things
		if err := logcmd.RunAndLogCommandContext(ctx, log, configCmd, opts...); err != nil {
			return err
		}

		if false {
			if err := kcfonfigValidate(configOptions[:i+1]); err != nil {
				return fmt.Errorf("failed to validate config after applying %v: %w", opts, err)
			}
		}

	}

	if false {
		if err := kcfonfigValidate(configOptions); err != nil {
			return fmt.Errorf("failed to validate config after scripts: %w", err)
		}
	}

	// run make olddefconfig to clean up the config file, and ensure that everything is in order
	if err := logcmd.RunAndLogCommandContext(ctx, log, MakeBinary, "olddefconfig"); err != nil {
		return err
	}

	// NB: some configuration options are only available in certain
	// kernels. We have no way of dealing with this currently.
	if err := kcfonfigValidate(configOptions); err != nil {
		log.Warnf("discrepancies in generated config: %s", err)
	}

	log.Info("configuration completed")
	return nil
}

func (kd *KernelsDir) buildKernel(ctx context.Context, log *logrus.Logger, kc *KernelConf) error {
	if err := CheckEnvironment(); err != nil {
		return err
	}

	srcDir := filepath.Join(kd.Dir, kc.Name)
	configFname := filepath.Join(srcDir, ".config")

	if exists, err := regularFileExists(configFname); err != nil {
		return err
	} else if !exists {
		log.Info("Configuring kernel")
		err = kd.configureKernel(ctx, log, kc)
		if err != nil {
			return fmt.Errorf("failed to configure kernel: %w", err)
		}
	}

	ncpus := fmt.Sprintf("%d", runtime.NumCPU())
	if err := logcmd.RunAndLogCommandContext(ctx, log, MakeBinary, "-C", srcDir, "-j", ncpus, "bzImage", "modules"); err != nil {
		return fmt.Errorf("buiding bzImage && modules failed: %w", err)
	}

	if err := logcmd.RunAndLogCommandContext(ctx, log, MakeBinary, "-C", srcDir, "tar-pkg"); err != nil {
		return fmt.Errorf("build dir failed: %w", err)
	}

	return nil
}
