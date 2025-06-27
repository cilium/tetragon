// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/cilium/little-vm-helper/pkg/arch"
	"github.com/cilium/little-vm-helper/pkg/logcmd"
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

func (kd *KernelsDir) ConfigureKernel(ctx context.Context, log *logrus.Logger, kernName string, targetArch string) error {
	kc := kd.KernelConfig(kernName)
	if kc == nil {
		return fmt.Errorf("kernel '%s' not found", kernName)
	}
	return kd.configureKernel(ctx, log, kc, targetArch)
}

func (kd *KernelsDir) RawConfigure(ctx context.Context, log *logrus.Logger, kernDir, kernName string, targetArch string) error {
	kc := kd.KernelConfig(kernName)
	return kd.rawConfigureKernel(ctx, log, kc, kernDir, targetArch)
}

func kConfigValidate(opts []ConfigOption) error {

	var ret error
	// we want to check that:
	//  - what is supposed to be enabled, is enabled
	//  - what is supposed to be disabled, is not enabled
	//  - what is supposed to be configured as module, is configured as a module

	type configState string

	const (
		enabledState  configState = "y"
		disabledState configState = "n"
		moduleState   configState = "m"
	)

	type OptMapVal struct {
		state   configState
		checked bool
	}

	optMap := make(map[string]OptMapVal)
	for _, opt := range opts {
		switch opt[0] {
		case "--enable":
			optMap[opt[1]] = OptMapVal{state: enabledState}
		case "--disable":
			optMap[opt[1]] = OptMapVal{state: disabledState}
		case "--module":
			optMap[opt[1]] = OptMapVal{state: moduleState}
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

	enabledOrModuleRe := regexp.MustCompile(`([a-zA-Z0-9_]+)=(y|m)`)
	disabledRe := regexp.MustCompile(`# ([a-zA-Z0-9_]+) is not set`)
	s := bufio.NewScanner(kcfg)
	for s.Scan() {
		txt := s.Text()
		var opt string
		var optState configState
		if match := enabledOrModuleRe.FindStringSubmatch(txt); len(match) > 2 {
			opt = match[1]
			// the regex can only match 'y' or 'm' so this should be correct
			optState = configState(match[2])
		} else if match := disabledRe.FindStringSubmatch(txt); len(match) > 1 {
			opt = match[1]
			optState = disabledState
		} else {
			continue
		}

		mapVal, ok := optMap[opt]
		if !ok {
			continue
		}

		mapVal.checked = true
		optMap[opt] = mapVal

		if mapVal.state != optState {
			ret = errors.Join(ret,
				fmt.Errorf("value %s misconfigured: expected: %q but seems to be %q based on %q",
					opt, mapVal.state, optState, txt))
		}

	}

	if err := s.Err(); err != nil {
		return err
	}

	for i, v := range optMap {
		if v.state == enabledState && !v.checked {
			ret = errors.Join(ret, fmt.Errorf("value %s enabled but not found", i))
		}
		if v.state == moduleState && !v.checked {
			ret = errors.Join(ret, fmt.Errorf("value %s configured as module but not found", i))
		}
	}

	return ret
}

func runAndLogMake(
	ctx context.Context,
	log *logrus.Logger,
	kc *KernelConf,
	makeArgs ...string,
) error {
	if len(kc.ExtraMakeArgs) > 0 {
		makeArgs = append(makeArgs, kc.ExtraMakeArgs...)
	}
	return logcmd.RunAndLogCommandContext(ctx, log, MakeBinary, makeArgs...)
}

func (kd *KernelsDir) rawConfigureKernel(
	ctx context.Context, log *logrus.Logger,
	kc *KernelConf, srcDir string, targetArch string,
	makePrepareArgs ...string,
) error {
	oldPath, err := os.Getwd()
	if err != nil {
		return err
	}

	// If the source directory does not exist, there is nothing to configure so let's fetch the
	// kernel
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		log.WithFields(logrus.Fields{
			"kernel": kc.Name,
			"srcDir": srcDir,
		}).Info("src directory does not exist, fetching kernel")
		kurl, err := kc.KernelURL()
		if err != nil {
			return err
		}
		if err := kurl.fetch(ctx, log, kd.Dir, kc.Name); err != nil {
			return err
		}
	}

	err = os.Chdir(srcDir)
	if err != nil {
		return fmt.Errorf("failed to chdir into %q: %w", srcDir, err)
	}
	defer os.Chdir(oldPath)

	configOptions := kd.Conf.getOptions(kc)

	if len(makePrepareArgs) > 0 {
		if err := runAndLogMake(ctx, log, kc, makePrepareArgs...); err != nil {
			return err
		}
	}

	configCmd := filepath.Join(".", "scripts", "config")
	for i, opts := range configOptions {
		// NB: we could do this in a single command, but doing it one-by-one makes it easier to debug things
		if err := logcmd.RunAndLogCommandContext(ctx, log, configCmd, opts...); err != nil {
			return err
		}

		if false {
			if err := kConfigValidate(configOptions[:i+1]); err != nil {
				return fmt.Errorf("failed to validate config after applying %v: %w", opts, err)
			}
		}

	}

	if false {
		if err := kConfigValidate(configOptions); err != nil {
			return fmt.Errorf("failed to validate config after scripts: %w", err)
		}
	}

	tarch, err := arch.NewArch(targetArch)
	if err != nil {
		return err
	}
	crossCompilationArgs := tarch.CrossCompileMakeArgs()
	olddefconfigMakeArgs := []string{"olddefconfig"}
	olddefconfigMakeArgs = append(olddefconfigMakeArgs, crossCompilationArgs...)

	// run make olddefconfig to clean up the config file, and ensure that everything is in order
	if err := runAndLogMake(ctx, log, kc, olddefconfigMakeArgs...); err != nil {
		return err
	}

	// NB: some configuration options are only available in certain
	// kernels. We have no way of dealing with this currently.
	if err := kConfigValidate(configOptions); err != nil {
		log.Warnf("discrepancies in generated config: %s", err)
	}

	log.Info("configuration completed")
	return nil
}

func (kd *KernelsDir) configureKernel(ctx context.Context, log *logrus.Logger, kc *KernelConf, targetArch string) error {
	srcDir := filepath.Join(kd.Dir, kc.Name)
	tarch, err := arch.NewArch(targetArch)
	if err != nil {
		return err
	}
	crossCompilationArgs := tarch.CrossCompileMakeArgs()
	configureMakeArgs := []string{"defconfig", "prepare"}
	configureMakeArgs = append(configureMakeArgs, crossCompilationArgs...)

	return kd.rawConfigureKernel(ctx, log, kc, srcDir, targetArch, configureMakeArgs...)

}

func (kd *KernelsDir) buildKernel(ctx context.Context, log *logrus.Logger, kc *KernelConf, targetArch string) error {
	if err := CheckEnvironment(); err != nil {
		return err
	}

	srcDir := filepath.Join(kd.Dir, kc.Name)
	configFname := filepath.Join(srcDir, ".config")

	if exists, err := regularFileExists(configFname); err != nil {
		return err
	} else if !exists {
		log.Info("Configuring kernel")
		err = kd.configureKernel(ctx, log, kc, targetArch)
		if err != nil {
			return fmt.Errorf("failed to configure kernel: %w", err)
		}
	}

	ncpus := fmt.Sprintf("%d", runtime.NumCPU())

	tarch, err := arch.NewArch(targetArch)
	if err != nil {
		return err
	}
	target := tarch.Target()
	buildMakeArgs := []string{"-C", srcDir, "-j", ncpus, target, "modules"}

	crossCompilationArgs := tarch.CrossCompileMakeArgs()
	buildMakeArgs = append(buildMakeArgs, crossCompilationArgs...)

	if err := runAndLogMake(ctx, log, kc, buildMakeArgs...); err != nil {
		return fmt.Errorf("buiding bzImage && modules failed: %w", err)
	}

	archiveMakeArgs := []string{"-C", srcDir, "tar-pkg"}
	archiveMakeArgs = append(archiveMakeArgs, crossCompilationArgs...)

	if err := runAndLogMake(ctx, log, kc, archiveMakeArgs...); err != nil {
		return fmt.Errorf("build dir failed: %w", err)
	}

	return nil
}
