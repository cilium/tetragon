// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/tests/e2e/state"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/support/kind"
)

const configPath = "/tmp/tetragon-e2e-kind.yaml"

const kindConfig = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: "/proc"
    containerPath: "/procRoot"
  - hostPath: "/tetragonExport"
    containerPath: "/tetragonExport"
  - hostPath: "/sys/fs/bpf"
    containerPath: "/sys/fs/bpf"
    propagation: Bidirectional
`

var (
	clusterName  string
	clusterImage string
)

func init() {
	flag.StringVar(&clusterName, "cluster-name", "tetragon-ci", "Set the name of the k8s cluster being used")
	// renovate: datasource=docker
	flag.StringVar(&clusterImage, "cluster-image", "kindest/node:v1.32.3", "Set the node image for the kind cluster")
}

// GetClusterName fetches the cluster name configured with -cluster-name or the temporary
// kind cluster name.
func GetClusterName() string {
	return clusterName
}

func SetMinKernelVersion() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources()

		nodeList := &corev1.NodeList{}
		r.List(ctx, nodeList)
		if len(nodeList.Items) < 1 {
			return ctx, fmt.Errorf("failed to list nodes in cluster")
		}

		var versions []string
		var versionsInt []int64

		for _, node := range nodeList.Items {
			name := node.Status.NodeInfo.MachineID
			kVersion := node.Status.NodeInfo.KernelVersion

			// vendors like to define kernel 4.14.128-foo but
			// everything after '-' is meaningless to us so toss it out
			release := strings.Split(kVersion, "-")
			kVersion = release[0]

			klog.Infof("Node %s has kernel version %s", name, kVersion)

			versions = append(versions, kVersion)
			versionsInt = append(versionsInt, kernels.KernelStringToNumeric(kVersion))
		}

		minimum := int64(math.MaxInt64)
		var minStr string
		for i := range versions {
			verStr := versions[i]
			verInt := versionsInt[i]

			if verInt < minimum {
				minimum = verInt
				minStr = verStr
			}
		}

		return context.WithValue(ctx, state.MinKernelVersion, minStr), nil
	}
}

func GetMinKernelVersion(t *testing.T, testenv env.Environment) string {
	version := new(string)
	feature := features.New("Get Minimum Kernel Version").
		Assess("Lookup Kernel Version", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			if v, ok := ctx.Value(state.MinKernelVersion).(string); ok {
				*version = v
			} else {
				assert.Fail(t, "Failed to get kernel version from ctx. Did setup complete properly?")
			}
			return ctx
		}).Feature()
	testenv.Test(t, feature)
	return *version
}

func writeKindConfig() error {
	f, err := os.Create(configPath)
	if err != nil {
		return err
	}

	_, err = f.WriteString(kindConfig)
	if err != nil {
		return err
	}

	return nil
}

// MaybeCreateTempKindCluster creates a new temporary kind cluster in case no kubeconfig file is
// specified on the command line.
func MaybeCreateTempKindCluster(testenv env.Environment, namePrefix string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if cfg.KubeconfigFile() == "" {
			name := envconf.RandomName(namePrefix, 16)
			clusterName = name
			klog.Infof("No kubeconfig specified, creating temporary kind cluster %s", name)
			var err error
			err = writeKindConfig()
			if err != nil {
				return ctx, err
			}
			ctx, err = envfuncs.CreateClusterWithConfig(kind.NewProvider(), name, configPath, kind.WithImage(clusterImage))(ctx, cfg)
			if err != nil {
				return ctx, err
			}
			// Automatically clean up the cluster when the test finishes
			testenv.Finish(deleteTempKindCluster(name))
			return context.WithValue(ctx, state.ClusterName, name), nil
		}
		return ctx, nil
	}
}

// deleteTempKindCluster deletes a new temporary kind cluster previously created using
// MaybeCreateTempKindCluster.
func deleteTempKindCluster(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.Infof("Deleting temporary kind cluster %s", clusterName)
		var err error
		ctx, err = envfuncs.DestroyCluster(clusterName)(ctx, cfg)
		if err != nil {
			return ctx, err
		}
		return context.WithValue(ctx, state.ClusterName, nil), nil
	}
}

// GetTempKindClusterName returns the name of the temporary kind cluster if it exists,
// otherwise it returns an empty string.
func GetTempKindClusterName(ctx context.Context) string {
	if name, ok := ctx.Value(state.ClusterName).(string); ok {
		return name
	}
	return ""
}
