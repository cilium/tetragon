// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func calculateSHA256(filePath string) (string, error) {
	cmd := exec.Command("sha256sum", filePath)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to calculate SHA256: %w", err)
	}

	// sha256sum output format: "<hash>  <filename>"
	fields := strings.Fields(string(output))
	if len(fields) < 1 {
		return "", errors.New("unexpected sha256sum output")
	}

	return fields[0], nil
}

func extractBuildIDFromFile(filePath string) (string, error) {
	// Use 'file' command to extract BuildID: file <path> | grep -oE "BuildID\[sha1\]=[a-f0-9]+" | cut -d= -f2
	cmd := exec.Command("sh", "-c", fmt.Sprintf("file %s | grep -oE \"BuildID\\[sha1\\]=[a-f0-9]+\" | cut -d= -f2", filePath))
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to extract build ID: %w", err)
	}

	buildID := strings.TrimSpace(string(output))
	if buildID == "" {
		return "", errors.New("no build ID found in binary")
	}

	return buildID, nil
}

func uprobePolicy(digests []string) string {
	path := testutils.RepoRootPath("contrib/tester-progs/nop")
	extra := ""
	if len(digests) > 0 {
		extra = "\n      binaryDigests:"
		for _, d := range digests {
			extra += fmt.Sprintf("\n        - \"%s\"", d)
		}
	}

	return fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
    name: "uprobe-digest-test"
spec:
    uprobes:
    - path: "%s"
      symbols:
      - "main"%s
`, path, extra)
}

func policyLoadMatchesExpectation(t *testing.T, policy string, shouldLoad bool) {
	t.Helper()

	createCrdFile(t, policy)
	tp, err := tracingpolicy.FromFile(testConfigFile)
	require.NoError(t, err, "failed to parse policy")

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	_, err = observertesthelper.GetDefaultObserver(
		t,
		ctx,
		tus.Conf().TetragonLib,
		observertesthelper.WithMyPid(),
	)
	require.NoError(t, err, "failed to initialize observer")

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	if shouldLoad {
		require.NoError(t, err, "policy should load")
	} else {
		require.Error(t, err, "policy should fail to load")
	}
}

func TestUprobeDigestScenarios(t *testing.T) {
	nop := testutils.RepoRootPath("contrib/tester-progs/nop")
	sha256Digest, err := calculateSHA256(nop)
	require.NoError(t, err)

	type testCase struct {
		name       string
		digests    func(*testing.T) []string
		shouldLoad bool
	}

	testCases := []testCase{
		{
			name:       "no digest",
			digests:    func(*testing.T) []string { return nil },
			shouldLoad: true,
		},
		{
			name:       "correct sha256",
			digests:    func(*testing.T) []string { return []string{"sha256:" + sha256Digest} },
			shouldLoad: true,
		},
		{
			name: "wrong sha256",
			digests: func(*testing.T) []string {
				return []string{"sha256:0000000000000000000000000000000000000000000000000000000000000000"}
			},
			shouldLoad: false,
		},
		{
			name:       "invalid format",
			digests:    func(*testing.T) []string { return []string{"sha256noseparator"} },
			shouldLoad: false,
		},
		{
			name:       "unsupported algorithm",
			digests:    func(*testing.T) []string { return []string{"md5:abc123"} },
			shouldLoad: false,
		},
		{
			name:       "case insensitive hash",
			digests:    func(*testing.T) []string { return []string{"sha256:" + strings.ToUpper(sha256Digest)} },
			shouldLoad: true,
		},
		{
			name: "build id",
			digests: func(t *testing.T) []string {
				buildID, err := extractBuildIDFromFile(nop)
				if err != nil || buildID == "" {
					t.Skip("binary has no build ID")
				}
				return []string{"build-id:" + buildID}
			},
			shouldLoad: true,
		},
		{
			name: "multiple digests any match",
			digests: func(*testing.T) []string {
				return []string{
					"sha256:0000000000000000000000000000000000000000000000000000000000000000",
					"sha256:" + sha256Digest,
				}
			},
			shouldLoad: true,
		},
		{
			name: "multiple digests all wrong",
			digests: func(*testing.T) []string {
				return []string{
					"sha256:1111111111111111111111111111111111111111111111111111111111111111",
					"sha256:2222222222222222222222222222222222222222222222222222222222222222",
				}
			},
			shouldLoad: false,
		},
		{
			name: "digest with spaces",
			digests: func(*testing.T) []string {
				return []string{"  sha256 : " + sha256Digest + "  "}
			},
			shouldLoad: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policyLoadMatchesExpectation(t, uprobePolicy(tc.digests(t)), tc.shouldLoad)
		})
	}
}
