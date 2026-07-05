// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/testutils/policytest/kube"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

// defaultInPodBinsDir is where the policytest image bakes the trigger binaries
// (contrib/tester-progs). The orchestrator may override it via --bindir.
const defaultInPodBinsDir = "/usr/local/lib/tetragon/tester-progs"

// inpodOpts holds the inputs for the in-pod runner, populated from flags.
type inpodOpts struct {
	grpcAddr  string
	binsDir   string
	namespace string
	podLabels map[string]string
}

// conf builds the policytest.Conf used by the in-pod runner. When namespace and
// podLabels are set, the generated policy is scoped to the test pod (see
// policytest.ScopePolicy).
func (o *inpodOpts) conf() *policytest.Conf {
	return &policytest.Conf{
		GrpcAddr:          o.grpcAddr,
		BinsDir:           o.binsDir,
		Namespace:         o.namespace,
		PodSelectorLabels: o.podLabels,
	}
}

// inpodCmd runs policy tests from inside a test pod, connecting to the
// node-local Tetragon agent over gRPC and emitting machine-readable results to
// stdout for the client-side orchestrator to collect. It is an internal
// entrypoint, not meant for direct use.
func inpodCmd() *cobra.Command {
	binsDir := defaultInPodBinsDir
	namespace := ""
	monitorMode := false
	var podLabels map[string]string
	var params map[string]string

	cmd := cobra.Command{
		Use:    "run-inpod",
		Short:  "Run Tetragon policy test(s) from within a test pod (internal)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			logLevel := slog.LevelInfo
			if common.Debug {
				logLevel = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

			paramValues := make(map[string]any)
			for k, v := range params {
				paramValues[k] = v
			}

			names := make(map[string]struct{})
			for _, arg := range args {
				names[arg] = struct{}{}
			}
			tests := policytest.AllPolicyTests.GetByFunction(func(t *policytest.T) bool {
				_, ok := names[t.Name]
				return ok
			})

			opts := inpodOpts{
				grpcAddr:  common.ServerAddress,
				binsDir:   binsDir,
				namespace: namespace,
				podLabels: podLabels,
			}

			// Some policytests read tus.Conf() (e.g. for the trigger's binary
			// name); initialize it so they don't panic outside `go test`.
			tus.SetConf(&tus.ConfigDefaults)

			ctx := context.Background()
			runner, err := policytest.NewLocalRunner(ctx, log, opts.conf())
			if err != nil {
				return fmt.Errorf("failed to start in-pod runner: %w", err)
			}
			defer runner.Close()

			var results []kube.TestResult
			for _, t := range tests {
				res := runner.RunTest(log, t, &policytest.TestConf{
					MonitorMode: monitorMode,
					ParamValues: paramValues,
				})
				results = append(results, kube.FromResult(t.Name, res))
			}

			data, err := kube.Encode(results)
			if err != nil {
				return err
			}
			// Prefix with the marker so the orchestrator can extract this line
			// from pod logs that also contain stderr logging.
			fmt.Fprintf(cmd.OutOrStdout(), "%s%s\n", kube.ResultMarker, data)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&binsDir, "bindir", binsDir, "path for test binaries directory")
	flags.StringVar(&namespace, "namespace", namespace, "namespace for the namespaced policy and test pod")
	flags.BoolVar(&monitorMode, "monitor-mode", monitorMode, "set the policy(-ies) in monitor mode before running the test(s)")
	flags.StringToStringVar(&podLabels, "pod-selector-label", map[string]string{}, "label(s) used to scope the policy to the test pod (podSelector)")
	flags.StringToStringVar(&params, "set-param", map[string]string{}, "Set a policy parameter")
	return &cmd
}
