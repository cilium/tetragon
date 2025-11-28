// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

// The /proc/PID/stat file consists of a single line of space-separated strings, where
// the 2nd string contains the process' comm. This string is wrapped in brackets but can
// contain spaces and brackets. The correct way to parse this stat string is to find all
// space-separated strings working backwards from the end until a string is found that
// ends in a space, then find the first string and everything left must be the comm.
func getProcStatStrings(procStat string) []string {
	var output []string

	// Build list of strings in reverse order
	oldIndex := len(procStat)
	index := strings.LastIndexByte(procStat, ' ')
	for index > 0 {
		output = append(output, procStat[index+1:oldIndex])
		if procStat[index-1] == ')' {
			break
		}
		oldIndex = index
		index = strings.LastIndexByte(procStat[:oldIndex], ' ')
	}

	if index == -1 {
		// Did not hit ')'
		output = append(output, procStat[:oldIndex])
	} else {
		// Find the comm and first field
		commIndex := strings.IndexByte(procStat, ' ')
		output = append(output, procStat[commIndex+1:index])
		output = append(output, procStat[:commIndex])
	}

	// Reverse the array
	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	}

	return output
}

// fillStatus returns the content of /proc/pid/status as Status
func fillStatus(file string, status *Status) error {
	path := filepath.Join(file, "status")
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s failed: %w", path, err)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 2 {
			continue
		}

		if fields[0] == "Uid:" {
			if len(fields) != 5 {
				return fmt.Errorf("reading Uid from %s failed: malformed input", path)
			}
			status.Uids = []string{fields[1], fields[2], fields[3], fields[4]}
		}

		if fields[0] == "Gid:" {
			if len(fields) != 5 {
				return fmt.Errorf("reading Gid from %s failed: malformed input", path)
			}
			status.Gids = []string{fields[1], fields[2], fields[3], fields[4]}
		}

		if len(status.Uids) > 0 && len(status.Gids) > 0 {
			break
		}
	}

	return nil
}

func fillLoginUid(file string, status *Status) error {
	path := filepath.Join(file, "loginuid")
	auid, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("ReadFile %s failed: %w", path, err)
	}

	status.LoginUid = strings.TrimRight(string(auid), "\n")

	return nil
}

func GetStatus(file string) (*Status, error) {
	var status Status
	err := fillStatus(file, &status)
	if err != nil {
		return nil, err
	}

	err = fillLoginUid(file, &status)
	if err != nil {
		return nil, err
	}

	return &status, nil
}

func GetProcStatStrings(file string) ([]string, error) {
	statline, err := os.ReadFile(filepath.Join(file, "stat"))
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %s /stat error", file)
	}
	return getProcStatStrings(string(statline)), nil
}

// GetSelfPid() Get current pid
//
// Returns:
//
//	Current pid from procfs and nil on success
//	Zero and error on failure
func GetSelfPid(procfs string) (uint64, error) {
	str, err := filepath.EvalSymlinks(filepath.Join(procfs, "self"))
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(filepath.Base(str), 10, 32)
}

// LogCurrentLSMContext() Logs the current LSM security context.
func LogCurrentSecurityContext() {
	lsms := map[string]string{
		"selinux":  "",
		"apparmor": "",
		"smack":    "",
	}

	logLSM := false
	for k := range lsms {
		path := ""
		if k == "selinux" {
			path = filepath.Join(option.Config.ProcFS, "/self/attr/current")
		} else {
			path = filepath.Join(option.Config.ProcFS, fmt.Sprintf("/self/attr/%s/current", k))
		}
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			lsms[k] = strings.TrimSpace(string(data))
			logLSM = true
		}
	}

	lockdown := ""
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err == nil && len(data) > 0 {
		values := strings.TrimSpace(string(data))
		i := strings.Index(values, "[")
		j := strings.Index(values, "]")
		if i >= 0 && j > i {
			lockdown = values[i+1 : j]
			logLSM = true
		}
		if lockdown == "confidentiality" {
			logger.GetLogger().Warn("Kernel Lockdown is in 'confidentiality' mode; Tetragon will fail to load BPF programs. See https://tetragon.io/docs/installation/faq/#kernel-lockdown for details.")
		}
	}

	if logLSM {
		/* Now log all LSM security so we can debug later in
		 * case some operations fail.
		 */
		logger.GetLogger().Info("Tetragon current security context",
			"SELinux", lsms["selinux"],
			"AppArmor", lsms["apparmor"],
			"Smack", lsms["smack"],
			"Lockdown", lockdown)
	}
}
