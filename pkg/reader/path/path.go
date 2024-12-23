// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package path

import (
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/cilium/tetragon/pkg/api/processapi"
)

func GetBinaryAbsolutePath(binary string, cwd string) string {
	if filepath.IsAbs(binary) {
		return binary
	}
	return filepath.Join(cwd, binary)
}

func FilePathFlagsToStr(flags uint32) string {
	if (flags & processapi.UnresolvedPathComponents) != 0 {
		return "unresolvedPathComponents"
	}
	return ""
}

func stickybitString(bits uint16, sticky string) byte {
	if 0 == bits {
		return 0
	}

	bits = bits >> 9
	for i := 2; i >= 0; i-- {
		if bits&(1<<uint(i)) != 0 {
			return sticky[i]
		}
	}

	return 0
}

func permString(bits uint16, rwx string, sticky byte) string {
	var str strings.Builder
	for i := 2; i >= 0; i-- {
		if bits&(1<<uint(i)) != 0 {
			if i == 0 && 0 != sticky {
				str.WriteByte(sticky)
			} else {
				str.WriteByte(rwx[i])
			}
		} else {
			if i == 0 && 0 != sticky {
				str.WriteByte(byte(unicode.ToUpper(rune(sticky))))
			} else {
				str.WriteByte('-')
			}
		}
	}
	return str.String()
}

func FilePathModeToStr(mode uint16) string {
	var str strings.Builder
	upcast_mode := uint32(mode)
	switch upcast_mode & syscall.S_IFMT {
	case syscall.S_IFBLK:
		str.WriteString("b")
	case syscall.S_IFCHR:
		str.WriteString("c")
	case syscall.S_IFDIR:
		str.WriteString("d")
	case syscall.S_IFIFO:
		str.WriteString("p")
	case syscall.S_IFLNK:
		str.WriteString("l")
	case syscall.S_IFREG:
		str.WriteString("-")
	case syscall.S_IFSOCK:
		str.WriteString("s")
	}

	str.WriteString(permString(mode>>6, "xwr", stickybitString(mode&syscall.S_ISUID, "tss")))
	str.WriteString(permString((mode>>3)&7, "xwr", stickybitString(mode&syscall.S_ISGID, "tss")))
	str.WriteString(permString(mode&7, "xwr", stickybitString(mode&syscall.S_ISVTX, "tss")))

	return str.String()
}
