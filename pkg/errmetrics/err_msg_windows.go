package errmetrics

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func GetErrorMessage(err uint16) (message string) {
	const flags uint32 = syscall.FORMAT_MESSAGE_FROM_SYSTEM
	buf := make([]uint16, 300)
	_, error := windows.FormatMessage(flags, 0, uint32(err), 0, buf, nil)
	if error != nil {
		return "unknown error code "
	}
	return windows.UTF16ToString(buf[:])
}
