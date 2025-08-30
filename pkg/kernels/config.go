// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kernels

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type Config int

const (
	CONFIG_AUDIT Config = iota
	CONFIG_BPF
	CONFIG_BPF_EVENTS
	CONFIG_BPF_JIT
	CONFIG_BPF_JIT_DEFAULT_ON
	CONFIG_BPF_KPROBE_OVERRIDE
	CONFIG_BPF_SYSCALL
	CONFIG_CGROUPS
	CONFIG_DEBUG_INFO_BTF
	CONFIG_DEBUG_INFO_BTF_MODULES
	CONFIG_FTRACE_SYSCALLS
	CONFIG_HAVE_BPF_JIT
	CONFIG_HAVE_EBPF_JIT
	CONFIG_SECURITY
)

type kernelConfig struct {
	name  string
	value string
}

var (
	getKernelConfig = sync.OnceValue(initKernelConfig)
	kernelConfigMap = map[Config]kernelConfig{
		CONFIG_AUDIT:                  {name: "CONFIG_AUDIT"},
		CONFIG_BPF:                    {name: "CONFIG_BPF"},
		CONFIG_BPF_EVENTS:             {name: "CONFIG_BPF_EVENTS"},
		CONFIG_BPF_JIT:                {name: "CONFIG_BPF_JIT"},
		CONFIG_BPF_JIT_DEFAULT_ON:     {name: "CONFIG_BPF_JIT_DEFAULT_ON"},
		CONFIG_BPF_KPROBE_OVERRIDE:    {name: "CONFIG_BPF_KPROBE_OVERRIDE"},
		CONFIG_BPF_SYSCALL:            {name: "CONFIG_BPF_SYSCALL"},
		CONFIG_CGROUPS:                {name: "CONFIG_CGROUPS"},
		CONFIG_DEBUG_INFO_BTF:         {name: "CONFIG_DEBUG_INFO_BTF"},
		CONFIG_DEBUG_INFO_BTF_MODULES: {name: "CONFIG_DEBUG_INFO_BTF_MODULES"},
		CONFIG_FTRACE_SYSCALLS:        {name: "CONFIG_FTRACE_SYSCALLS"},
		CONFIG_HAVE_BPF_JIT:           {name: "CONFIG_HAVE_BPF_JIT"},
		CONFIG_HAVE_EBPF_JIT:          {name: "CONFIG_HAVE_EBPF_JIT"},
		CONFIG_SECURITY:               {name: "CONFIG_SECURITY"},
	}
)

func setKernelConfigMap(key, value string) {
	for index, config := range kernelConfigMap {
		if config.name == key {
			config.value = value
			kernelConfigMap[index] = config
			break
		}
	}
}

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

			if key != "" && value != "" {
				setKernelConfigMap(key, value)
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

	err = scanKernelConfig(gzReader)
	if err != nil {
		return err
	}

	return nil
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

	err = scanKernelConfig(file)
	if err != nil {
		return err
	}

	return nil
}

func initKernelConfig() error {
	if err := initKernelProcConfigGz(); err != nil {
		return initKernelBootConfig()
	}

	return nil
}

// DetectConfig checks if a kernel config option is enabled
// It first tries /proc/config.gz, then looks for config file in /boot for the current kernel
func DetectConfig(conf Config) (bool, error) {
	err := getKernelConfig()
	if err != nil {
		return false, err
	}

	if val, ok := kernelConfigMap[conf]; ok {
		// Only check for CONFIG_XXX=y or CONFIG_XXX=m. When the value is a string or number,
		// it's mostly treated as a kernel parameter rather than a feature switch,
		// so we temporarily filter these out.
		if val.value == "y" || val.value == "m" {
			return true, nil
		}
	}

	return false, nil
}
