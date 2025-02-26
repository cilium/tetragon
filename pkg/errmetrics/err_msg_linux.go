package errmetrics

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func GetErrorMessage(err uint16) (message string) {
	return unix.ErrnoName(syscall.Errno(err))
}
