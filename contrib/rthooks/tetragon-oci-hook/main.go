// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

// OCI hook for tetragon
// See: https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks
//
// This is an implementation of an OCI hook that can be used to notify the tetragon agent about
// events such as container creation. It can be used by any container runtime that implements the
// OCI Runtime Specification.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	logFname                        = flag.String("log-fname", "/var/log/tetragon-oci-hook.log", "log output filename")
	logLevel                        = flag.String("log-level", "info", "log level")
	agentAddress                    = flag.String("grpc-address", "unix:///var/run/cilium/tetragon/tetragon.sock", "gRPC address for connecting to the tetragon agent")
	grpcTimeout                     = flag.Duration("grpc-timeout", 10*time.Second, "timeout for connecting to agent via gRPC")
	disableGrpc                     = flag.Bool("disable-grpc", false, "do not connect to gRPC address. Instead, write a message to log")
	annotationsNamespaceDefaultKeys = []string{"io.kubernetes.pod.namespace", "io.kubernetes.cri.sandbox-namespace"}
	annotationsNamespaceKeys        = flag.StringSlice(
		"annotations-namespace-key",
		annotationsNamespaceDefaultKeys,
		"Runtime annotations  key for kubernetes namespace")
	failCelUser = flag.String(
		"fail-cel-expr",
		"",
		"CEL expression to decide whether to fail (and stop container from starting) or not.")
	failAllowNamespaces = flag.StringSlice(
		"fail-allow-namespaces",
		[]string{"kube-system"},
		"Command will not fail for specified namespaces. The namespace is determined by runtime annotation labels. Flag will be ignored if fail-cel-expr is set.")
)

func readJsonSpec(fname string) (*specs.Spec, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", fname, err)
	}

	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	return &spec, nil
}

func getTime() string {
	s, _ := time.Now().UTC().MarshalText()
	return string(s)
}

func hookRequest(req *tetragon.RuntimeHookRequest) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	connCtx, connCancel := context.WithTimeout(ctx, *grpcTimeout)
	defer connCancel()
	conn, err := grpc.DialContext(connCtx, *agentAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("connecting to agent (%s) failed: %s", err, *agentAddress)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	_, err = client.RuntimeHook(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func getCgroupPath(spec *specs.Spec) (string, error) {
	var cgroupPath string
	if spec.Linux == nil {
		return "", fmt.Errorf("Linux is empty in spec: %+v", spec)
	}

	cgroupPath = spec.Linux.CgroupsPath
	if strings.Contains(cgroupPath, "/") {
		return cgroupPath, nil
	}

	// There are some cases where CgroupsPath  is specified as "slice:prefix:name"
	// From runc --help
	//   --systemd-cgroup    enable systemd cgroup support, expects cgroupsPath to be of form "slice:prefix:name"
	//                       for e.g. "system.slice:runc:434234"
	//
	// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/specconv/spec_linux.go#L655-L663
	parts := strings.Split(cgroupPath, ":")
	if len(parts) == 3 {
		var err error
		slice, scope, name := parts[0], parts[1], parts[2]
		slice, err = systemd.ExpandSlice(slice)
		if err != nil {
			return "", fmt.Errorf("failed to parse cgroup path: %s (%s does not seem to be a slice)", cgroupPath, slice)
		}
		// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/cgroups/systemd/common.go#L95-L101
		if !strings.HasSuffix(name, ".slice") {
			name = scope + "-" + name + ".scope"
		}
		return filepath.Join(slice, name), nil
	}

	return "", fmt.Errorf("Unknown cgroup path: %s", cgroupPath)
}

// NB: the second argument is only used in case of an error, so disable revive's complains
// revive:disable:error-return
func createContainerHook(log *logrus.Entry) (error, map[string]string) {

	// rootDir is the current directory
	rootDir, err := os.Getwd()
	var configName string
	if err != nil {
		log.Warnf("failed to retrieve CWD: %s, using '.'", err)
		rootDir = "."
	}

	configPaths := []string{
		"../config.json",          // containerd
		"../userdata/config.json", // cri-o
	}

	configName = ""
	for _, path := range configPaths {
		p := filepath.Join(rootDir, path)
		if _, err := os.Stat(p); err == nil {
			configName = p
			break
		}
	}

	if configName == "" {
		return fmt.Errorf("failed to find spec file. Tried the following dirs: %v", configPaths), nil
	}

	// We use the config.json file to get the cgroup path. An alternative option is to use
	// /proc/self/cgroup, but parsing the spec seems like a better option.
	var cgroupPath string
	spec, err := readJsonSpec(configName)
	if err != nil {
		log.WithError(err).Warnf("failed to read spec file: %s", configName)
	} else if cgroupPath, err = getCgroupPath(spec); err != nil {
		log.Warnf("error getting cgroup path: %v", err)
	}

	// if have no information whatsover, do not contact the agent
	if cgroupPath == "" && rootDir == "" {
		return fmt.Errorf("unable to determine either RootDir or cgroupPath, bailing out"), nil
	}

	req := &tetragon.RuntimeHookRequest{
		Event: &tetragon.RuntimeHookRequest_CreateContainer{
			CreateContainer: &tetragon.CreateContainer{
				CgroupsPath: cgroupPath,
				RootDir:     rootDir,
				Annotations: spec.Annotations,
			},
		},
	}

	if *disableGrpc {
		log.WithFields(logrus.Fields{
			"req-cgroups":     cgroupPath,
			"req-rootdir":     rootDir,
			"req-annotations": spec.Annotations,
			// NB: omit annotations since they are too noisy
		}).Warn("hook request (gRPC disabled)")
		return nil, nil
	}

	err = hookRequest(req)
	if err != nil {
		log.WithFields(logrus.Fields{
			"req-cgroups": cgroupPath,
			"req-rootdir": rootDir,
			// NB: omit annotations since they are too noisy
		}).Warn("hook request to agent failed")
		return err, spec.Annotations
	}

	log.WithField("req", req).Info("hook request to agent succeeded")
	return nil, nil
}

func checkFail(log *logrus.Entry, annotations map[string]string) {
	var prog *celProg
	var err error

	if expr := *failCelUser; expr != "" {
		prog, err = celUserExpr(expr)
	} else {
		prog, err = celAllowNamespaces(*failAllowNamespaces)
	}

	if err != nil {
		log.WithError(err).Fatal("failCheck failed")
	}

	log.Debugf("running fail check with annotations: %v", annotations)
	fail, err := prog.RunFailCheck(annotations)
	if err != nil {
		log.WithError(err).Fatal("failCheck failed")
	}

	if fail {
		log.Fatal("failCheck determined failure. Failing")
	}

	log.Info("failCheck determined that we should not fail this container, even if there was an error")
}

func main() {
	flag.Parse()

	log := logrus.New()
	log.SetOutput(&lumberjack.Logger{
		Filename:   *logFname,
		MaxSize:    50, // megabytes
		MaxBackups: 3,
		MaxAge:     7, //days
	})

	if lvl, err := logrus.ParseLevel(*logLevel); err == nil {
		log.SetLevel(lvl)
	} else {
		log.WithField("log-level", *logLevel).Warn("unknonwn log level, ignoring")
	}

	args := flag.Args()
	if len(args) < 1 {
		log.Warn("hook called without event, bailing out")
		return
	}

	hookName := args[0]
	switch hookName {
	case "createContainer":
		log := log.WithField("hook", "create-container").WithField("start-time", getTime())
		err, annotations := createContainerHook(log)
		if err != nil {
			checkFail(log, annotations)
		}
	case "createRuntime":
		// do nothing
	case "poststop":
		// do nothing
	default:
		log.WithField("hook", hookName).Warn("hook called with unknown hook")
	}

	return
}
