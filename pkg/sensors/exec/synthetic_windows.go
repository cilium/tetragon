// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"github.com/cilium/tetragon/pkg/logger"
)

func RegisterSyntheticEvents() {
	logger.GetLogger().Warn("Synthetic events are only supported on Linux")
}
