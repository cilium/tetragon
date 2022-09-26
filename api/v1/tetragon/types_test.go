// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tetragon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseIsType(t *testing.T) {
	ger := GetEventsResponse{
		Event: &GetEventsResponse_ProcessExec{},
	}

	assert.True(t, EventType_PROCESS_EXEC.ResponseIsType(&ger))
	assert.False(t, EventType_PROCESS_EXIT.ResponseIsType(&ger))
	assert.False(t, EventType_UNDEF.ResponseIsType(&ger))
}

func TestEventIsType(t *testing.T) {
	event := ProcessExec{}

	assert.True(t, EventType_PROCESS_EXEC.EventIsType(&event))
	assert.False(t, EventType_PROCESS_EXIT.EventIsType(&event))
	assert.False(t, EventType_UNDEF.EventIsType(&event))
}
