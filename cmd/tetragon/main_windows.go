// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

func logCurrentSecurityContext() {
}

func initHostNamespaces() error {
	return nil
}

func checkProcFS() {

}

func initCachedBTF(_, _ string) error {
	return nil
}

func checkStructAlignments() error {
	return nil
}

func setNetNSDir() {
}

// resolveUnixSocketPath is a no-op on Windows: the agent does not
// advertise or open a unix socket sidecar listener, since the default
// Linux path (/var/run/tetragon/tetragon.sock) is not available there.
func resolveUnixSocketPath(_ string) (string, bool) {
	return "", false
}
