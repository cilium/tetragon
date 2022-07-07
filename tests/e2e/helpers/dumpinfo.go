// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/cilium-e2e/pkg/e2ecluster/e2ehelpers"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/state"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

var (
	TetragonContainerName = "tetragon"
	TetragonJsonPathname  = "/var/run/cilium/tetragon/tetragon.log"
)

type TestEnvFunc = func(ctx context.Context, cfg *envconf.Config, t *testing.T) (context.Context, error)

func MaybeDumpInfo(keepRegardless bool) TestEnvFunc {
	return func(ctx context.Context, cfg *envconf.Config, t *testing.T) (context.Context, error) {
		if !t.Failed() && !keepRegardless {
			klog.Info("Test passed, skipping log export due to test configuration")
			return ctx, nil
		}

		opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
		if !ok {
			return ctx, fmt.Errorf("failed to find Tetragon install options. Did the test setup install Tetragon?")
		}

		dir, err := createExportDir(t)
		if err != nil {
			return ctx, fmt.Errorf("failed to create export dir: %w", err)
		}

		klog.InfoS("Dumping test data", "dir", dir)
		dumpCheckers(ctx, dir)

		if ports, ok := ctx.Value(state.PromForwardedPorts).(map[string]int); ok {
			for podName, port := range ports {
				dumpMetrics(fmt.Sprint(port), podName, dir)
			}
		}

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(opts.Namespace)

		podList := &corev1.PodList{}
		if err = r.List(
			ctx,
			podList,
			resources.WithLabelSelector(fmt.Sprintf("app.kubernetes.io/name=%s", opts.DaemonSetName)),
		); err != nil {
			return ctx, err
		}

		for _, pod := range podList.Items {
			if err := extractJson(&pod, dir); err != nil {
				klog.ErrorS(err, "Failed to extract json events")
			}
			if err := extractLogs(&pod, dir, true); err != nil {
				klog.ErrorS(err, "Failed to extract previous tetragon logs")
			}
			if err := extractLogs(&pod, dir, false); err != nil {
				klog.ErrorS(err, "Failed to extract tetragon logs")
			}
			dumpBpftool(ctx, client, dir, pod.Namespace, pod.Name, TetragonContainerName)
		}

		return ctx, nil
	}
}

func createExportDir(t *testing.T) (string, error) {
	return ioutil.TempDir("", fmt.Sprintf("tetragon.e2e.%s.*", t.Name()))
}

func extractJson(pod *corev1.Pod, exportDir string) error {
	return kubectlCp(pod.Namespace,
		pod.Name,
		TetragonContainerName,
		TetragonJsonPathname,
		filepath.Join(exportDir, fmt.Sprintf("tetragon.%s.json", pod.Name)))
}

func extractLogs(pod *corev1.Pod, exportDir string, prev bool) error {
	var fname string
	if prev {
		fname = fmt.Sprintf("tetragon.%s.prev.log", pod.Name)
	} else {
		fname = fmt.Sprintf("tetragon.%s.log", pod.Name)
	}
	return kubectlLogs(filepath.Join(exportDir, fname),
		pod.Namespace,
		pod.Name,
		TetragonContainerName,
		prev)
}

func kubectlCp(podNamespace, podName, containerName, src, dst string) error {
	args := fmt.Sprintf("cp -c %s %s/%s:%s %s", containerName, podNamespace, podName, src, dst)
	cmd := exec.Command("kubectl", strings.Fields(args)...)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run kubectl %s: %w", args, err)
	}

	return nil
}

func kubectlLogs(fname, podNamespace, podName, containerName string, prev bool) error {
	args := fmt.Sprintf("logs -c %s -n %s %s", containerName, podNamespace, podName)
	if prev {
		args += " --previous"
	}
	cmd := exec.Command("kubectl", strings.Fields(args)...)
	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run kubectl %s: %w", args, err)
	}

	if err := os.WriteFile(fname, stdout.Bytes(), os.FileMode(0o644)); err != nil {
		return fmt.Errorf("failed to write logs to file %s: %w", fname, err)
	}

	return nil
}

func dumpCheckers(ctx context.Context, exportDir string) {
	if checkers, ok := ctx.Value(state.EventCheckers).(map[string]*checker.RPCChecker); ok {
		for name, checker := range checkers {
			if checker == nil {
				klog.Warningf("nil checker encountered %s", name)
				continue
			}

			yamlStr, err := checker.CheckerYaml()
			if err != nil {
				klog.Warningf("failed to dump checker yaml for %s: %w", name, err)
			}

			fname := filepath.Join(exportDir, fmt.Sprintf("%s.eventchecker.yaml", name))
			if err := os.WriteFile(fname, []byte(yamlStr), os.FileMode(0o644)); err != nil {
				klog.Warningf("failed to write checker yaml to file %s: %w", fname, err)
			}

			fname = filepath.Join(exportDir, fmt.Sprintf("%s.eventchecker.log", name))
			if err := os.WriteFile(fname, checker.Logs(), os.FileMode(0o644)); err != nil {
				klog.Warningf("failed to write checker logs to file %s: %w", fname, err)
			}
		}
		return
	}
	klog.Info("No checker info to dump")
}

// dumpMetrics dumps the metrics for a port
func dumpMetrics(port string, podName string, exportDir string) {
	// contact metrics server
	metricsAddr := fmt.Sprintf("http://localhost:%s/metrics", port)
	klog.V(2).Info("contacting metrics server", "addr", metricsAddr)

	resp, err := http.Get(metricsAddr)
	if err != nil {
		klog.ErrorS(err, "failed to contact metrics server", "addr", metricsAddr)
		return
	}
	defer resp.Body.Close()

	buff := new(bytes.Buffer)
	if _, err = buff.ReadFrom(resp.Body); err != nil {
		klog.ErrorS(err, "error reading metrics server response", "addr", metricsAddr)
		return
	}

	fname := filepath.Join(exportDir, fmt.Sprintf("tetragon.%s.metrics", podName))
	if err := os.WriteFile(fname, buff.Bytes(), os.FileMode(0o644)); err != nil {
		klog.ErrorS(err, "failed to write to metrics file", "file", fname, "addr", metricsAddr)
	}
}

// dumpBpftool dumps bpftool progs and maps for a pod
func dumpBpftool(ctx context.Context, client klient.Client, exportDir, podNamespace, podName, containerName string) {
	if err := runBpftool(ctx, client, exportDir, fmt.Sprintf("tetragon.%s.progs", podName), podNamespace, podName, containerName, "prog", "show"); err != nil {
		klog.ErrorS(err, "failed to dump programs", "pod", podName, "namespace", podNamespace)
	}
	if err := runBpftool(ctx, client, exportDir, fmt.Sprintf("tetragon.%s.maps", podName), podNamespace, podName, containerName, "map", "show"); err != nil {
		klog.ErrorS(err, "failed to dump maps", "pod", podName, "namespace", podNamespace)
	}
	if err := runBpftool(ctx, client, exportDir, fmt.Sprintf("tetragon.%s.cgroups", podName), podNamespace, podName, containerName, "cgroup", "tree"); err != nil {
		klog.ErrorS(err, "failed to dump cgroup tree", "pod", podName, "namespace", podNamespace)
	}
}

func runBpftool(ctx context.Context, client klient.Client, exportDir, fname, podNamespace, podName, containerName string, args ...string) error {
	cmd := append([]string{"bpftool"}, args...)

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	if err := e2ehelpers.ExecInPod(ctx,
		client,
		podNamespace,
		podName,
		containerName,
		stdout,
		stderr,
		cmd); err != nil {
		return fmt.Errorf("failed to run %s: %w", cmd, err)
	}

	var err error
	buff := new(bytes.Buffer)
	buff.WriteString("-------------------- stdout starts here --------------------\n")
	if _, err = buff.ReadFrom(stdout); err != nil {
		klog.ErrorS(err, "error reading stdout", "cmd", cmd)
	}
	buff.WriteString("-------------------- stderr starts here --------------------\n")
	if _, err = buff.ReadFrom(stderr); err != nil {
		klog.ErrorS(err, "error reading stdout", "cmd", cmd)
	}
	buff.WriteString("------------------------------------------------------------\n")

	fname = filepath.Join(exportDir, fname)
	if err := os.WriteFile(fname, buff.Bytes(), os.FileMode(0o644)); err != nil {
		klog.ErrorS(err, "failed to write to bpftool output file", "file", fname)
	}

	return nil
}
