// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/vmtests"
	"golang.org/x/sys/unix"
)

// NB(kkourt): this is meant for running this program as init. It kinda works,
// but I think creates more trouble that being useful at this point. I'll leave
// the code for now, just in case we want to actually use it at some point. If
// it keeping the code creates issues, let's just delete it.
func doPID0() {
	// mount proc and other filesystems that we need
	if err := unix.Mount("none", "/proc", "proc", 0, ""); err != nil {
		fmt.Printf("failed to mount proc: %v\n", err)
	}

	if err := unix.Mount("none", "/sys", "sysfs", 0, ""); err != nil {
		fmt.Printf("failed to mount sysfs: %v\n", err)
	}

	if err := unix.Mount("none", "/sys/kernel/debug", "debugfs", 0, ""); err != nil {
		fmt.Printf("failed to mount debugfs: %v\n", err)
	}

	if err := unix.Mount("none", "/sys/kernel/debug", "debugfs", 0, ""); err != nil {
		fmt.Printf("failed to mount debugfs: %v\n", err)
	}

	if err := unix.Mount("/dev/root", "/", "", unix.MS_REMOUNT, ""); err != nil {
		fmt.Printf("failed to remount /: %v\n", err)
	}

	// TODO: do mount -a, to mount everything in /etc/fstab

}

// https://github.com/aisola/go-coreutils/blob/6eb4c2d5305ac4795a562573fbd9b39d6cbdfc10/uname/uname.go#L98
// utsnameToString converts the utsname to a string and returns it.
func utsnameToString(unameArray [65]byte) string {
	var byteString [65]byte
	var indexLength int
	for ; unameArray[indexLength] != 0; indexLength++ {
		byteString[indexLength] = uint8(unameArray[indexLength])
	}
	return string(byteString[:indexLength])
}

// printInfo prints a short message similar to unmame
func printInfo() {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		fmt.Printf("failed to execute Uname: %v", err)
	}

	fmt.Printf("%s %s %s %s\n", utsnameToString(uname.Sysname), utsnameToString(uname.Nodename), utsnameToString(uname.Release), utsnameToString(uname.Version))
}

// tester performs the following
//   - reads the configuration from the configuration file
//   - runs the tests
//   - marshalls the results in results.json
func tester() int {
	var err error
	var data []byte
	var conf vmtests.Conf
	if data, err = os.ReadFile(vmtests.ConfFile); err == nil {
		if err = json.Unmarshal(data, &conf); err != nil {
			fmt.Printf("failed to load config file %s: %v", vmtests.ConfFile, err)
			return 1
		}
	} else {
		// TODO: add proper parameters to handle local execution use-case
		tetragonDir := "."
		resultsDir, err := os.MkdirTemp(tetragonDir, "tetragon-tester-")
		if err != nil {
			fmt.Printf("failed to create results directory: %v\n", err)
			return 1
		}

		conf = vmtests.Conf{
			NoPowerOff:  true,
			TetragonDir: tetragonDir,
			ResultsDir:  resultsDir,
		}
		fmt.Printf("no configuration found: %v. Using default configuration for local execution (resultsdir:%s)\n", err, resultsDir)
	}

	if !conf.NoPowerOff {
		defer func() {
			fmt.Println("tetragon-tester shutting down the machine...")
			os.Stdout.Sync()
			time.Sleep(100 * time.Millisecond)
			if err := os.WriteFile("/proc/sysrq-trigger", []byte("o"), 0777); err != nil {
				fmt.Printf("failed to use syseq-trigger to shutdown machine")
				return
			}
			// wait for the powerdown before init is killed to avoid confusing messages from the kernel
			for {
				time.Sleep(1 * time.Second)
			}
		}()
	}

	if os.Getpid() == 1 {
		doPID0()
	}

	printInfo()
	err = vmtests.Run(&conf)
	if err != nil {
		fmt.Printf("tetragon-tester: error running vmtests: %v\n", err)
		return 1
	}

	return 0
}

func main() {
	os.Exit(tester())
}
