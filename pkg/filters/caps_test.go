// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func TestCapFilterAny(t *testing.T) {
	f := []*tetragon.Filter{{Capabilities: &tetragon.CapFilter{Effective: &tetragon.CapFilterSet{
		Any: []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_SYS_ADMIN, tetragon.CapabilitiesType_CAP_BPF},
	}}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&CapsFilter{}})
	require.NoError(t, err)
	process := tetragon.Process{Cap: &tetragon.Capabilities{}}
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &process,
				},
			},
		},
	}
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.True(t, fl.MatchOne(&ev), "both defined")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
		tetragon.CapabilitiesType_CAP_SYS_BOOT,
	}
	assert.True(t, fl.MatchOne(&ev), "both defined with extra")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
	}
	assert.True(t, fl.MatchOne(&ev), "only cap_bpf defined")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.True(t, fl.MatchOne(&ev), "only cap_sysadmin_defined")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_AUDIT_READ,
	}
	assert.False(t, fl.MatchOne(&ev), "extra only")
	process.Cap.Effective = []tetragon.CapabilitiesType{}
	assert.False(t, fl.MatchOne(&ev), "empty")
	process.Cap.Effective = nil
	assert.False(t, fl.MatchOne(&ev), "nil")
}

func TestCapFilterAll(t *testing.T) {
	f := []*tetragon.Filter{{Capabilities: &tetragon.CapFilter{Effective: &tetragon.CapFilterSet{
		All: []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_SYS_ADMIN, tetragon.CapabilitiesType_CAP_BPF},
	}}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&CapsFilter{}})
	require.NoError(t, err)
	process := tetragon.Process{Cap: &tetragon.Capabilities{}}
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &process,
				},
			},
		},
	}
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.True(t, fl.MatchOne(&ev), "both defined")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
		tetragon.CapabilitiesType_CAP_SYS_BOOT,
	}
	assert.True(t, fl.MatchOne(&ev), "both defined with extra")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
	}
	assert.False(t, fl.MatchOne(&ev), "only cap_bpf defined")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.False(t, fl.MatchOne(&ev), "only cap_sysadmin_defined")
	process.Cap.Effective = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_AUDIT_READ,
	}
	assert.False(t, fl.MatchOne(&ev), "extra only")
	process.Cap.Effective = []tetragon.CapabilitiesType{}
	assert.False(t, fl.MatchOne(&ev), "empty")
	process.Cap.Effective = nil
	assert.False(t, fl.MatchOne(&ev), "nil")
}

func TestCapFilterExactly(t *testing.T) {
	f := []*tetragon.Filter{{Capabilities: &tetragon.CapFilter{Inheritable: &tetragon.CapFilterSet{
		Exactly: []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_SYS_ADMIN, tetragon.CapabilitiesType_CAP_BPF},
	}}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&CapsFilter{}})
	require.NoError(t, err)
	process := tetragon.Process{Cap: &tetragon.Capabilities{}}
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &process,
				},
			},
		},
	}
	process.Cap.Inheritable = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.True(t, fl.MatchOne(&ev), "both defined")
	process.Cap.Inheritable = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
		tetragon.CapabilitiesType_CAP_SYS_BOOT,
	}
	assert.False(t, fl.MatchOne(&ev), "both defined with extra")
	process.Cap.Inheritable = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
	}
	assert.False(t, fl.MatchOne(&ev), "only cap_bpf defined")
	process.Cap.Inheritable = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.False(t, fl.MatchOne(&ev), "only cap_sysadmin_defined")
	process.Cap.Inheritable = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_AUDIT_READ,
	}
	assert.False(t, fl.MatchOne(&ev), "extra only")
	process.Cap.Inheritable = []tetragon.CapabilitiesType{}
	assert.False(t, fl.MatchOne(&ev), "empty")
	process.Cap.Inheritable = nil
	assert.False(t, fl.MatchOne(&ev), "nil")
}

func TestCapFilterNone(t *testing.T) {
	f := []*tetragon.Filter{{Capabilities: &tetragon.CapFilter{Permitted: &tetragon.CapFilterSet{
		None: []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_SYS_ADMIN, tetragon.CapabilitiesType_CAP_BPF},
	}}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&CapsFilter{}})
	require.NoError(t, err)
	process := tetragon.Process{Cap: &tetragon.Capabilities{}}
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &process,
				},
			},
		},
	}
	process.Cap.Permitted = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.False(t, fl.MatchOne(&ev), "both defined")
	process.Cap.Permitted = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
		tetragon.CapabilitiesType_CAP_SYS_BOOT,
	}
	assert.False(t, fl.MatchOne(&ev), "both defined with extra")
	process.Cap.Permitted = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_BPF,
	}
	assert.False(t, fl.MatchOne(&ev), "only cap_bpf defined")
	process.Cap.Permitted = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_SYS_ADMIN,
	}
	assert.False(t, fl.MatchOne(&ev), "only cap_sysadmin_defined")
	process.Cap.Permitted = []tetragon.CapabilitiesType{
		tetragon.CapabilitiesType_CAP_AUDIT_READ,
	}
	assert.True(t, fl.MatchOne(&ev), "extra only")
	process.Cap.Permitted = []tetragon.CapabilitiesType{}
	assert.True(t, fl.MatchOne(&ev), "empty")
	process.Cap.Permitted = nil
	assert.True(t, fl.MatchOne(&ev), "nil")
}
