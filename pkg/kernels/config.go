// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kernels

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"golang.org/x/sys/unix"
)

type Config string

const (
	CONFIG_AUDIT                  Config = "CONFIG_AUDIT"
	CONFIG_AUDITSYSCALL           Config = "CONFIG_AUDITSYSCALL"
	CONFIG_BPF                    Config = "CONFIG_BPF"
	CONFIG_BPF_EVENTS             Config = "CONFIG_BPF_EVENTS"
	CONFIG_BPF_JIT                Config = "CONFIG_BPF_JIT"
	CONFIG_BPF_JIT_DEFAULT_ON     Config = "CONFIG_BPF_JIT_DEFAULT_ON"
	CONFIG_BPF_KPROBE_OVERRIDE    Config = "CONFIG_BPF_KPROBE_OVERRIDE"
	CONFIG_BPF_SYSCALL            Config = "CONFIG_BPF_SYSCALL"
	CONFIG_CGROUPS                Config = "CONFIG_CGROUPS"
	CONFIG_DEBUG_INFO_BTF         Config = "CONFIG_DEBUG_INFO_BTF"
	CONFIG_DEBUG_INFO_BTF_MODULES Config = "CONFIG_DEBUG_INFO_BTF_MODULES"
	CONFIG_FTRACE_SYSCALLS        Config = "CONFIG_FTRACE_SYSCALLS"
	CONFIG_HAVE_BPF_JIT           Config = "CONFIG_HAVE_BPF_JIT"
	CONFIG_HAVE_EBPF_JIT          Config = "CONFIG_HAVE_EBPF_JIT"
	CONFIG_SECURITY               Config = "CONFIG_SECURITY"
)

var (
	getKernelConfig = sync.OnceValue(initKernelConfig)
	kernelConfigMap = map[Config]string{
		CONFIG_AUDIT:                  "n",
		CONFIG_AUDITSYSCALL:           "n",
		CONFIG_BPF:                    "n",
		CONFIG_BPF_EVENTS:             "n",
		CONFIG_BPF_JIT:                "n",
		CONFIG_BPF_JIT_DEFAULT_ON:     "n",
		CONFIG_BPF_KPROBE_OVERRIDE:    "n",
		CONFIG_BPF_SYSCALL:            "n",
		CONFIG_CGROUPS:                "n",
		CONFIG_DEBUG_INFO_BTF:         "n",
		CONFIG_DEBUG_INFO_BTF_MODULES: "n",
		CONFIG_FTRACE_SYSCALLS:        "n",
		CONFIG_HAVE_BPF_JIT:           "n",
		CONFIG_HAVE_EBPF_JIT:          "n",
		CONFIG_SECURITY:               "n",
	}
)

func scanKernelConfig(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if key == "" || value == "" {
				continue
			}

			if _, ok := kernelConfigMap[Config(key)]; ok {
				kernelConfigMap[Config(key)] = value
			}
		}
	}

	return scanner.Err()
}

func initKernelProcConfigGz() error {
	file, err := os.Open("/proc/config.gz")
	if err != nil {
		return err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	return scanKernelConfig(gzReader)
}

func initKernelBootConfig() error {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return err
	}

	kernelRelease := strings.TrimRight(string(uname.Release[:]), "\x00")
	configPath := "/boot/config-" + kernelRelease
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return scanKernelConfig(file)
}

func initKernelConfig() error {
	if err := initKernelProcConfigGz(); err != nil {
		return initKernelBootConfig()
	}

	return nil
}

// DetectConfig checks if a kernel config option is enabled
// It first tries /proc/config.gz, then looks for config file in /boot for the current kernel
func DetectConfig(conf Config) bool {
	if err := getKernelConfig(); err != nil {
		logger.GetLogger().Error("Detecting kernel config failed", logfields.Error, err)
		return false
	}

	if val, ok := kernelConfigMap[conf]; ok {
		// Only check for CONFIG_XXX=y or CONFIG_XXX=m. When the value is a string or number,
		// it's mostly treated as a kernel parameter rather than a feature switch,
		// so we temporarily filter these out.
		if val == "y" || val == "m" {
			return true
		}
	}

	return false
}

func LogConfigs() string {
	if err := getKernelConfig(); err != nil {
		logger.GetLogger().Error("Detecting kernel config failed", logfields.Error, err)
		return ""
	}

	var items []string
	for k, v := range kernelConfigMap {
		items = append(items, fmt.Sprintf("%s:%s", k, v))
	}
	sort.Strings(items)

	return strings.Join(items, " ")
}
