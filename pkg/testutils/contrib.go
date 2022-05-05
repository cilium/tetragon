//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package testutils

import (
	"path/filepath"
	"runtime"
)

// ContribPath retrieves contrib path (useful to find scripts and other files)
func ContribPath(fname string) string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", "contrib", fname)
}
