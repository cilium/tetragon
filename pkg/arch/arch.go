package arch

import (
	"fmt"
	"runtime"
	"strings"
)

var supportedArchPrefix = map[string]string{"amd64": "__x64_", "arm64": "__arm64_"}

func addSyscallPrefix(symbol string, arch string) (string, error) {
	for prefix_arch, prefix := range supportedArchPrefix {
		if strings.HasPrefix(symbol, prefix) {
			// check that the prefix found is the correct one
			if prefix_arch != arch {
				return "", fmt.Errorf("expecting %s and got %s", supportedArchPrefix[arch], prefix)
			}
			return symbol, nil
		}
	}
	if prefix, found := supportedArchPrefix[arch]; found {
		return prefix + symbol, nil
	}
	return "", fmt.Errorf("unsupported architecture %s", arch)
}

// AddSyscallPrefix detects if the symbol is already prefixed with arch specific
// prefix in the form of "__x64_" or "__arm64_", and if not, adds it based on
// provided arch.
//
// Note that cilium/ebpf, retries to attach to an arch specific version of the
// symbol after a failure thus making possible to attach to "sys_listen" which
// will fail and retry with the corrected "__arm64_sys_listen" if you are
// running on arm64. See https://github.com/cilium/ebpf/pull/304.  However, this
// causes Tetragon users to believe that two symbols exist (following the same
// example) "__arm64_sys_listen" and "sys_listen", which results in differents
// events.  Because we actually know if a call is a syscall, we can pre-format
// the symbol directly here to allow the user to specify the "sys_listen"
// version while only registering the real symbol "__arm64_sys_listen".
func AddSyscallPrefix(symbol string) (string, error) {
	return addSyscallPrefix(symbol, runtime.GOARCH)
}

// MustAddSyscallPrefix is like AddSyscallPrefix but panics if the arch is
// unsupported or if the symbol has already a prefix that doesn't correspond to
// the running arch.
//
// It's a helper supposed to be used only in testing code.
func MustAddSyscallPrefix(symbol string) string
