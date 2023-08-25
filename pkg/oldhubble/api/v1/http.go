// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	pb "github.com/cilium/cilium/api/v1/flow"
)

// LooseCompareHTTP returns true if both HTTP flows are loosely identical. This
// means that the following fields must match:
//   - Code
//   - Method
//   - Url
//   - Protocol
func LooseCompareHTTP(a, b *pb.HTTP) bool {
	return a.Code == b.Code && a.Method == b.Method && a.Url == b.Url && a.Protocol == b.Protocol
}
