package ktime

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKtime(t *testing.T) {
	time1, err := NanoTimeSince(0)
	assert.NoError(t, err)
	assert.Greater(t, time1.Milliseconds(), int64(0))
	time2, err := NanoTimeSince(0)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, time2, time1)
}

func TestBoottime(t *testing.T) {
	time1, err := NanoTimeSince(0)
	assert.NoError(t, err)
	ktime1, err := DecodeKtime(time1.Nanoseconds(), false)
	assert.NoError(t, err)
	assert.Greater(t, ktime1.UnixMilli(), int64(0))
}
