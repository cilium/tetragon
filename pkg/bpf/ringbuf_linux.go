// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bpf

import "path/filepath"

var (
	ringbufEventsMapName = "tg_rb_events"
	RingBufEventsMapName = filepath.Join(MapPrefixPath(), ringbufEventsMapName)
)
