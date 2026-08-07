// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

func GetProcessID(pid uint32, _ uint64) string {
	return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%d:%d:%d", pid, pid, pid))
}

// ParseProcessID decodes an execId produced by GetProcessID, returning the
// pid it encodes. The ktime is not encoded in the process id on Windows,
// so it is always returned as 0.
func ParseProcessID(execId string) (pid uint32, ktime uint64, err error) {
	decoded, err := base64.StdEncoding.DecodeString(execId)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to decode process id %q: %w", execId, err)
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 3 {
		return 0, 0, fmt.Errorf("invalid process id %q", execId)
	}

	pid64, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid pid in process id %q: %w", execId, err)
	}

	return uint32(pid64), 0, nil
}
