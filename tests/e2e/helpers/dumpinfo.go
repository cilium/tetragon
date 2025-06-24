// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package helpers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers/gops"
	"github.com/cilium/tetragon/tests/e2e/state"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

var (
	TetragonContainerName         = "tetragon"
	TetragonOperatorContainerName = "tetragon-operator"
	TetragonJSONPathname          = "/var/run/cilium/tetragon/tetragon.log"
)

type TestEnvFunc = func(ctx context.Context, cfg *envconf.Config, t *testing.T) (context.Context, error)

func DumpInfo(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
	opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
	if !ok {
		return ctx, errors.New("failed to find Tetragon install options. Did the test setup install Tetragon?")
	}

	exportDir, err := GetExportDir(ctx)
	if err != nil {
		return ctx, err
	}

	klog.InfoS("Dumping test data", "dir", exportDir)
	dumpCheckers(ctx, exportDir)

	client, err := cfg.NewClient()
	if err != nil {
		return ctx, err
	}
	r := client.Resources(opts.Namespace)

	if err := dumpPodSummary("pods.txt", exportDir); err != nil {
		klog.ErrorS(err, "Failed to dump pod summary")
	}

	podList := &corev1.PodList{}
	if err = r.List(
		ctx,
		podList,
		resources.WithLabelSelector("app.kubernetes.io/name="+opts.DaemonSetName),
	); err != nil {
		return ctx, err
	}

	for _, pod := range podList.Items {
		if err := extractJSON(&pod, exportDir); err != nil {
			klog.ErrorS(err, "Failed to extract json events")
		}
		if err := extractLogs(&pod, TetragonContainerName, exportDir, true); err != nil {
			klog.InfoS("Failed to extract previous tetragon logs", "err", err)
		}
		if err := extractLogs(&pod, TetragonContainerName, exportDir, false); err != nil {
			klog.ErrorS(err, "Failed to extract tetragon logs")
		}
		if err := describeTetragonPod(&pod, exportDir); err != nil {
			klog.ErrorS(err, "Failed to describe tetragon pods")
		}
		dumpBpftool(ctx, client, exportDir, pod.Namespace, pod.Name, TetragonContainerName)
	}

	operatorPodList := &corev1.PodList{}
	if err = r.List(
		ctx,
		operatorPodList,
		resources.WithLabelSelector("app.kubernetes.io/name=tetragon-operator"),
	); err != nil {
		return ctx, err
	}

	for _, pod := range operatorPodList.Items {
		if err := extractLogs(&pod, TetragonOperatorContainerName, exportDir, true); err != nil {
			klog.InfoS("Failed to extract previous tetragon-operator logs", "error", err)
		}
		if err := extractLogs(&pod, TetragonOperatorContainerName, exportDir, false); err != nil {
			klog.ErrorS(err, "Failed to extract tetragon-operator logs")
		}
		if err := describeTetragonPod(&pod, exportDir); err != nil {
			klog.ErrorS(err, "Failed to describe tetragon-operator pods")
		}
	}

	return ctx, nil
}

func CreateExportDir(ctx context.Context, name string) (context.Context, error) {
	dir, err := GetExportDir(ctx)
	if err == nil {
		klog.V(2).InfoS("export dir already exists, skipping creation", "name", name, "dir", dir)
		return ctx, nil
	}

	dir, err = os.MkdirTemp("", fmt.Sprintf("tetragon.e2e.%s.*", name))
	if err != nil {
		return ctx, err
	}

	klog.InfoS("created export dir", "name", name, "dir", dir)

	return context.WithValue(ctx, state.ExportDir, dir), nil
}

func GetExportDir(ctx context.Context) (string, error) {
	exportDir, ok := ctx.Value(state.ExportDir).(string)
	if !ok {
		return "", errors.New("export dir has not been created. Call runner.CreateExportDir() first")
	}

	return exportDir, nil
}

func extractJSON(pod *corev1.Pod, exportDir string) error {
	return kubectlCp(pod.Namespace,
		pod.Name,
		TetragonContainerName,
		TetragonJSONPathname,
		filepath.Join(exportDir, fmt.Sprintf("tetragon.%s.json", pod.Name)))
}

func extractLogs(pod *corev1.Pod, containerName, exportDir string, prev bool) error {
	var fname string
	if prev {
		fname = fmt.Sprintf("tetragon.%s.prev.log", pod.Name)
	} else {
		fname = fmt.Sprintf("tetragon.%s.log", pod.Name)
	}
	return kubectlLogs(filepath.Join(exportDir, fname),
		pod.Namespace,
		pod.Name,
		containerName,
		prev)
}

func describeTetragonPod(pod *corev1.Pod, exportDir string) error {
	fname := fmt.Sprintf("tetragon.%s.describe", pod.Name)
	return kubectlDescribe(filepath.Join(exportDir, fname),
		pod.Namespace,
		pod.Name)
}

func dumpPodSummary(fname, exportDir string) error {
	cmd := exec.Command("kubectl", strings.Fields("get pods -A")...)
	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run kubectl get pods -A: %w", err)
	}

	fname = filepath.Join(exportDir, fname)
	if err := os.WriteFile(fname, stdout.Bytes(), os.FileMode(0o644)); err != nil {
		return fmt.Errorf("failed to write pod summary to file %s: %w", fname, err)
	}

	return nil
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

func kubectlDescribe(fname, podNamespace, podName string) error {
	args := fmt.Sprintf("describe -n %s pods/%s", podNamespace, podName)
	cmd := exec.Command("kubectl", strings.Fields(args)...)
	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run kubectl %s: %w", args, err)
	}

	if err := os.WriteFile(fname, stdout.Bytes(), os.FileMode(0o644)); err != nil {
		return fmt.Errorf("failed to write describe output to file %s: %w", fname, err)
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
				klog.ErrorS(err, "failed to dump checker yaml", "name", name)
			}

			fname := filepath.Join(exportDir, name+".eventchecker.yaml")
			if err := os.WriteFile(fname, []byte(yamlStr), os.FileMode(0o644)); err != nil {
				klog.ErrorS(err, "failed to write checker yaml to file", "file", fname)
			}

			fname = filepath.Join(exportDir, name+".eventchecker.log")
			if err := os.WriteFile(fname, checker.Logs(), os.FileMode(0o644)); err != nil {
				klog.ErrorS(err, "failed to write checker logs to file", "file", fname)
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

// StartMetricsDumper starts a goroutine that dumps metrics at a regular interval until
// the context is done. We want to do this in case the pod crashes or gets restarted
// during a failing test. This way we can at least have a snapshot of the metrics to look
// back on.
func StartMetricsDumper(ctx context.Context, exportDir string, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-ticker.C:
				if ports, ok := ctx.Value(state.PromForwardedPorts).(map[string]int); ok {
					for podName, port := range ports {
						dumpMetrics(strconv.Itoa(port), podName, exportDir)
					}
				} else {
					klog.V(4).Info("failed to retrieve metrics portforward, refusing to dump metrics")
				}
			case <-ctx.Done():
				if ports, ok := ctx.Value(state.PromForwardedPorts).(map[string]int); ok {
					for podName, port := range ports {
						dumpMetrics(strconv.Itoa(port), podName, exportDir)
					}
				} else {
					klog.V(4).Info("failed to retrieve metrics portforward, refusing to dump metrics")
				}
				return
			}
		}
	}()
}

// dumpGops dumps the gops heap and memstats
func dumpGops(port int, podName string, exportDir string) {
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		klog.ErrorS(err, "failed to resolve gops address")
		return
	}
	klog.V(2).Info("contacting gops agent", "addr", addr)

	out, err := gops.DumpHeapProfile(*addr)
	if err != nil {
		klog.ErrorS(err, "failed to dump heap profile", "addr", addr)
		return
	}
	fname := filepath.Join(exportDir, fmt.Sprintf("tetragon.%s.heap", podName))
	if err := os.WriteFile(fname, out, os.FileMode(0o644)); err != nil {
		klog.ErrorS(err, "failed to write to heap file", "file", fname, "addr", addr)
	}

	out, err = gops.DumpMemStats(*addr)
	if err != nil {
		klog.ErrorS(err, "failed to dump memstats", "addr", addr)
		return
	}
	fname = filepath.Join(exportDir, fmt.Sprintf("tetragon.%s.memstats", podName))
	if err := os.WriteFile(fname, out, os.FileMode(0o644)); err != nil {
		klog.ErrorS(err, "failed to write to memstats file", "file", fname, "addr", addr)
	}
}

// StartGopsDumper starts a goroutine that dumps gops information at a regular interval
// until the context is done. We want to do this in case the pod crashes or gets restarted
// during a failing test. This way we can at least have a snapshot of the gops dumps to look
// back on.
func StartGopsDumper(ctx context.Context, exportDir string, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-ticker.C:
				if ports, ok := ctx.Value(state.GopsForwardedPorts).(map[string]int); ok {
					for podName, port := range ports {
						dumpGops(port, podName, exportDir)
					}
				} else {
					klog.V(4).Info("failed to retrieve gops portforward, refusing to dump gops")
				}
			case <-ctx.Done():
				if ports, ok := ctx.Value(state.PromForwardedPorts).(map[string]int); ok {
					for podName, port := range ports {
						dumpGops(port, podName, exportDir)
					}
				} else {
					klog.V(4).Info("failed to retrieve gops portforward, refusing to dump gops")
				}
				return
			}
		}
	}()
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

// runBpftool runs bpftool with a specific set of arguments, dumping its output into
// a file inside exportDir.
func runBpftool(ctx context.Context, client klient.Client, exportDir, fname, podNamespace, podName, containerName string, args ...string) error {
	out, err := RunCommand(ctx, client, podNamespace, podName, containerName, "bpftool", args...)
	if err != nil {
		klog.ErrorS(err, "failed to run bpftool")
	}

	fname = filepath.Join(exportDir, fname)
	if err := os.WriteFile(fname, out, os.FileMode(0o644)); err != nil {
		klog.ErrorS(err, "failed to write to bpftool output file", "file", fname)
	}

	return nil
}
