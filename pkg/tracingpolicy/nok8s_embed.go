// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package tracingpolicy

import (
	_ "embed"
)

//go:embed schemas/tracingpolicy-cilium.io.json
var tracingpolicyJSONSchema []byte
