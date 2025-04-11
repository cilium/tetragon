// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package server

import "testing"

func TestSplitListenAddr(t *testing.T) {
	type testCase struct {
		arg string

		expectedErr bool
		proto, addr string
	}
	testCases := []testCase{
		{
			arg:   "unix:///var/run/tetragon/tetragon.sock",
			proto: "unix",
			addr:  "/var/run/tetragon/tetragon.sock",
		}, {
			arg:   "localhost:54321",
			proto: "tcp",
			addr:  "localhost:54321",
		}, {
			arg:   "localhost",
			proto: "tcp",
			addr:  "localhost:54321",
		}, {
			// NB: expect error on relative paths
			arg:         "unix://var/run/tetragon/tetragon.sock",
			expectedErr: true,
		},
	}

	for _, c := range testCases {
		proto, addr, err := SplitListenAddr(c.arg)
		if c.expectedErr {
			if err == nil {
				t.Fatalf("expected error for %s", c.arg)
			}
			continue
		}

		if err != nil {
			t.Fatalf("unexpected error for %s: %s", c.arg, err)
		}

		if proto != c.proto {
			t.Fatalf("Proto (%s) did not match expected value (%s) for %s", proto, c.proto, c.arg)
		}

		if addr != c.addr {
			t.Fatalf("Addr (%s) did not match expected value (%s) for %s", addr, c.addr, c.arg)
		}

		t.Logf("case %+v is OK!", c)
	}

}
