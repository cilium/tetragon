// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func calculateSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
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

func policyLoadMatchesExpectation(t *testing.T, policy string, expectedHookStatus tetragon.HookStatus) {
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
	require.NoError(t, err, "policy should load")

	statusRes, err := observer.GetSensorManager().ListTracingPolicies(ctx, "")
	require.NoError(t, err, "failed to list tracing policies")

	var policyStatus *tetragon.TracingPolicyStatus
	for _, s := range statusRes.Policies {
		if s.GetName() == "uprobe-digest-test" {
			policyStatus = s
			break
		}
	}
	require.NotNil(t, policyStatus, "failed to find tracing policy status")
	sensor_info := policyStatus.GetSensorInfo()
	require.Len(t, sensor_info, 1, "expected one sensor info")
	require.Len(t, sensor_info[0].GetHookInfo(), 1, "expected one per-hook status")
	require.Equal(t, expectedHookStatus, sensor_info[0].GetHookInfo()[0].GetStatus(), "unexpected hook status")
}

func TestUprobeDigestNoDigest(t *testing.T) {
	policyLoadMatchesExpectation(t, uprobePolicy(nil), tetragon.HookStatus_STATUS_LOADED)
}

func TestUprobeDigestCorrectSHA256(t *testing.T) {
	nop := testutils.RepoRootPath("contrib/tester-progs/nop")
	digest, err := calculateSHA256(nop)
	require.NoError(t, err)

	policyLoadMatchesExpectation(t, uprobePolicy([]string{"sha256:" + digest}), tetragon.HookStatus_STATUS_LOADED)
}

func TestUprobeDigestWrongSHA256(t *testing.T) {
	policyLoadMatchesExpectation(
		t,
		uprobePolicy([]string{"sha256:0000000000000000000000000000000000000000000000000000000000000000"}),
		tetragon.HookStatus_STATUS_DIGEST_REJECTED,
	)
}

func TestUprobeDigestInvalidFormat(t *testing.T) {
	policyLoadMatchesExpectation(t, uprobePolicy([]string{"sha256noseparator"}), tetragon.HookStatus_STATUS_DIGEST_REJECTED)
}

func TestUprobeDigestUnsupportedAlgorithm(t *testing.T) {
	policyLoadMatchesExpectation(t, uprobePolicy([]string{"md5:abc123"}), tetragon.HookStatus_STATUS_DIGEST_REJECTED)
}

func TestUprobeDigestCaseInsensitive(t *testing.T) {
	nop := testutils.RepoRootPath("contrib/tester-progs/nop")
	digest, err := calculateSHA256(nop)
	require.NoError(t, err)

	policyLoadMatchesExpectation(t, uprobePolicy([]string{"sha256:" + strings.ToUpper(digest)}), tetragon.HookStatus_STATUS_LOADED)
}

func TestUprobeDigestBuildID(t *testing.T) {
	nop := testutils.RepoRootPath("contrib/tester-progs/nop")
	buildID, err := extractBuildIDFromFile(nop)
	if err != nil || buildID == "" {
		t.Skip("binary has no build ID")
	}

	policyLoadMatchesExpectation(t, uprobePolicy([]string{"build-id:" + buildID}), tetragon.HookStatus_STATUS_LOADED)
}
func TestUprobeDigestMultipleDigestsAnyMatch(t *testing.T) {
	nop := testutils.RepoRootPath("contrib/tester-progs/nop")
	digest, err := calculateSHA256(nop)
	require.NoError(t, err)

	// First digest is wrong, second is correct
	digests := []string{
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"sha256:" + digest,
	}
	policyLoadMatchesExpectation(t, uprobePolicy(digests), tetragon.HookStatus_STATUS_LOADED)
}

func TestUprobeDigestMultipleDigestsAllWrong(t *testing.T) {
	// All digests are wrong
	wrongDigests := []string{
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"sha256:2222222222222222222222222222222222222222222222222222222222222222",
	}
	policyLoadMatchesExpectation(t, uprobePolicy(wrongDigests), tetragon.HookStatus_STATUS_DIGEST_REJECTED)
}
