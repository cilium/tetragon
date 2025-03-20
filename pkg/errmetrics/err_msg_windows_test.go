package errmetrics

import (
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMessage(t *testing.T) {
	s1 := GetErrorMessage(uint16(syscall.ERROR_ACCESS_DENIED))
	assert.Equal(t, strings.HasPrefix(s1, "Access is denied."), true)

	s2 := GetErrorMessage(uint16(syscall.ERROR_INSUFFICIENT_BUFFER))
	assert.Equal(t, strings.HasPrefix(s2, "The data area passed to a system call is too small."), true)

}
