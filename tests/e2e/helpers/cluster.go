// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package helpers

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/support/kind"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/tests/e2e/state"
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
	flag.StringVar(&clusterImage, "cluster-image", "kindest/node:v1.36.1", "Set the node image for the kind cluster")
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
			return ctx, errors.New("failed to list nodes in cluster")
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

// createTempKindCluster writes kindCfg to configPath and creates a temporary
// kind cluster from it, registering automatic cleanup. When a kubeconfig is
// provided on the command line it attaches to that existing cluster instead.
func createTempKindCluster(testenv env.Environment, namePrefix, kindCfg string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if cfg.KubeconfigFile() != "" {
			return ctx, nil
		}
		name := envconf.RandomName(namePrefix, 16)
		clusterName = name
		klog.Infof("No kubeconfig specified, creating temporary kind cluster %s", name)
		if err := os.WriteFile(configPath, []byte(kindCfg), 0o600); err != nil {
			return ctx, err
		}
		ctx, err := envfuncs.CreateClusterWithConfig(kind.NewProvider(), name, configPath, kind.WithImage(clusterImage))(ctx, cfg)
		if err != nil {
			return ctx, err
		}
		// Automatically clean up the cluster when the test finishes
		testenv.Finish(deleteTempKindCluster(name))
		return context.WithValue(ctx, state.ClusterName, name), nil
	}
}

// MaybeCreateTempKindCluster creates a new temporary kind cluster in case no kubeconfig file is
// specified on the command line.
func MaybeCreateTempKindCluster(testenv env.Environment, namePrefix string) env.Func {
	return createTempKindCluster(testenv, namePrefix, kindConfig)
}

// MaybeCreateTempKindClusterWithConfig behaves like MaybeCreateTempKindCluster but
// creates the temporary cluster from the supplied kind config YAML (e.g. a
// multi-node config). Tests that require more nodes than are present should skip.
func MaybeCreateTempKindClusterWithConfig(testenv env.Environment, namePrefix, kindCfg string) env.Func {
	return createTempKindCluster(testenv, namePrefix, kindCfg)
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

// LoadImageToMinikubeEnvFunc loads a container image into the minikube cluster via
// `minikube image load`. This is the minikube equivalent of
// envfuncs.LoadDockerImageToCluster for KinD.
func LoadImageToMinikubeEnvFunc(_ string, image string, _ ...string) env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		klog.InfoS("Loading image into minikube", "image", image)

		cmd := exec.Command("minikube", "image", "load", image)
		if out, err := cmd.CombinedOutput(); err != nil {
			return ctx, fmt.Errorf("minikube image load %s: %w\n%s", image, err, out)
		}

		// The name of locally build images doesn't contain a registry prefix
		// like "docker.io/". This name, without the registry prefix, is also
		// what helm uses in the Kubernetes Deployment.
		//
		// When executing `minikube image load` with the containerd container
		// runtime, the image in minikube is tagged with the registry prefix
		// "docker.io/" even if the image name doesn't contain it locally.
		// By itself this poses no problem because with docker and containerd
		// you can reference `docker.io/mycontainer` without the `docker.io`
		// prefix as `mycontainer`.
		//
		// However, with cri-o as minikube container runtime, the image is
		// loaded with a `localhost/` prefix instead of `docker.io/. Since
		// `localhost/mycontainer` cannot be referenced as `mycontainer`, we are
		// re-tagging the any `localhost/` images with `docker.io` since also
		// cri-o allows referencing `docker.io/mycontainer` as `mycontainer`.
		// this way we can keep the `mycontainer` reference in the helm chart.
		//
		// When the user manually sets the `E2E_AGENT` variable for the e2e
		// target in the Makefile with an full image e.g. from quay.io, this
		// re-tagging fails silently, since there isn't any `localhost/` image.
		cmd = exec.Command("minikube", "image", "tag", "localhost/"+image, "docker.io/"+image)
		if out, err := cmd.CombinedOutput(); err != nil {
			return ctx, fmt.Errorf("minikube image tag %s: %w\n%s", image, err, out)
		}
		return ctx, nil
	}
}
