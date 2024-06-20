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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	binDir                          = getBinaryDir()
	defaultLogFname                 = filepath.Join(binDir, "tetragon-oci-hook.log")
	defaultConfFile                 = filepath.Join(binDir, "tetragon-oci-hook.json")
	defaultAgentAddress             = "unix:///var/run/cilium/tetragon/tetragon.sock"
	defaultAnnotationsNamespaceKeys = "io.kubernetes.pod.namespace,io.kubernetes.cri.sandbox-namespace"
	defaultAllowNamspaces           = "kube-system"
)

var cliConf struct {
	LogFname            string        `name:"log-fname" default:"${defLogFname}" help:"log output filename."`
	LogLevel            string        `name:"log-level" default:"info" help:"log level"`
	AgentAddr           string        `name:"grpc-address" default:"${defAgentAddress}" help:"Tetragon agent gRPC address"`
	GrpcTimeout         time.Duration `name:"grpc-timeout" default:"10s" help:"timeout for connecting to the agent"`
	DisableGrpc         bool          `name:"disable-grpc" default:false help:"do not connect to the agent. Instead, write a message to the log"`
	JustPrintConfig     bool          `name:"just-print-config" default:false help:"just print the config and exit"`
	AnnNamespaceKeys    []string      `name:"annotations-namespace-key" default:"${defAnnotationsNamespaceKeys}" help:"Runtime annotation keys for accessing k8s namespace"`
	FailCelUser         string        `name:"fail-cel-expr" help:"CEL expression to decide whether to fail (and stop container from starting) or not"`
	FailAllowNamespaces []string      `name:"fail-allow-namespaces" default:"${defAllowNamespaces}" help:"The hook will not fail for the specified namespaces, as determined by runtime annotation labels. Flag will be ignored if fail-cel-expr is set."`

	HookName string `arg:"" name:"hook"`
}

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

	connCtx, connCancel := context.WithTimeout(ctx, cliConf.GrpcTimeout)
	defer connCancel()
	conn, err := grpc.DialContext(connCtx, cliConf.AgentAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("connecting to agent (%s) failed: %s", err, cliConf.AgentAddr)
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

func containerNameFromAnnotations(annotations map[string]string) string {
	// containerd
	if val, ok := annotations["io.kubernetes.cri.container-name"]; ok {
		return val
	}

	// crio
	if val, ok := annotations["io.kubernetes.container.name"]; ok {
		return val
	}

	return ""
}

// NB: the second argument is only used in case of an error, so disable revive's complains
// revive:disable:error-return
func createContainerHook(log *slog.Logger) (error, map[string]string) {

	// rootDir is the current directory
	rootDir, err := os.Getwd()
	var configName string
	if err != nil {
		log.Warn("failed to retrieve CWD, using '.'",
			"error", err)
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
		log.Warn("failed to read spec file", "name", configName, "error", err)
	} else if cgroupPath, err = getCgroupPath(spec); err != nil {
		log.Warn("error getting cgroup path", "error", err)
	}

	// if have no information whatsover, do not contact the agent
	if cgroupPath == "" && rootDir == "" {
		return fmt.Errorf("unable to determine either RootDir or cgroupPath, bailing out"), nil
	}

	containerName := containerNameFromAnnotations(spec.Annotations)

	req := &tetragon.RuntimeHookRequest{
		Event: &tetragon.RuntimeHookRequest_CreateContainer{
			CreateContainer: &tetragon.CreateContainer{
				CgroupsPath:   cgroupPath,
				RootDir:       rootDir,
				Annotations:   spec.Annotations,
				ContainerName: containerName,
			},
		},
	}

	log = log.With(
		"req-cgroups", cgroupPath,
		"req-rootdir", rootDir,
		"req-containerName", containerName,
	)
	if log.Enabled(context.TODO(), slog.LevelDebug) {
		// NB: only add annotations in debug level since they are too noisy
		log = log.With("req-annotations", spec.Annotations)
	}

	if cliConf.DisableGrpc {
		log.Info("gRPC was disabled, so will not be contacting the agent")
		return nil, nil
	}

	err = hookRequest(req)
	if err != nil {
		log.Warn("hook request to the agent failed", "err", err)
		return err, spec.Annotations
	}

	log.Info("hook request to agent succeeded")
	return nil, nil
}

func checkFail(log *slog.Logger, prog *celProg, annotations map[string]string) error {
	var err error

	log.Debug("running fail check", "annotations", annotations)
	fail, err := prog.RunFailCheck(annotations)
	if err != nil {
		return fmt.Errorf("failed to run failCheck: %w", err)
	}

	if fail {
		return errors.New("failCheck determined that we should fail")
	}

	log.Info("failCheck determined that we should not fail this container, even if there was an error")
	return nil
}

func failTestProg() (*celProg, error) {
	var ret *celProg
	var err error
	if expr := cliConf.FailCelUser; expr != "" {
		ret, err = celUserExpr(expr)
	} else {
		ret, err = celAllowNamespaces(cliConf.FailAllowNamespaces)
	}
	return ret, err
}

type logHandler struct {
	slog.Handler
}

func (lh *logHandler) Handle(ctx context.Context, r slog.Record) error {
	err := lh.Handler.Handle(ctx, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing to logger: %v\n", err)
	}
	return err
}

func main() {

	ctx := kong.Parse(&cliConf,
		kong.Vars{
			"defLogFname":                 defaultLogFname,
			"defAgentAddress":             defaultAgentAddress,
			"defAnnotationsNamespaceKeys": defaultAnnotationsNamespaceKeys,
			"defAllowNamespaces":          defaultAllowNamspaces,
		},
		kong.Configuration(kong.JSON, defaultConfFile),
	)

	if kongCmd := ctx.Command(); kongCmd != "<hook>" {
		fmt.Fprintf(os.Stderr, "unexpected parsing result: %s", kongCmd)
		os.Exit(1)
	}

	if cliConf.JustPrintConfig {
		fmt.Printf("%+v\n", cliConf)
		os.Exit(0)
	}

	var logLevel slog.Level
	var logLevelArgError bool
	if err := logLevel.UnmarshalText([]byte(cliConf.LogLevel)); err != nil {
		logLevel = slog.LevelInfo
		logLevelArgError = true
	}

	log := slog.New(&logHandler{slog.NewJSONHandler(
		&lumberjack.Logger{
			Filename:   cliConf.LogFname,
			MaxSize:    50, // megabytes
			MaxBackups: 3,
			MaxAge:     7, //days
		},
		&slog.HandlerOptions{
			Level: logLevel,
		},
	)})

	if logLevelArgError {
		log.Warn("was not able to parse logLevel, using default",
			"arg", cliConf.LogLevel,
			"default", logLevel)
	}

	failTestProg, err := failTestProg()
	if err != nil {
		log.Warn("error in creating fail test prog, bailing out", "errro", err)
		os.Exit(1)
	}

	switch cliConf.HookName {
	case "createContainer":
		log = log.With(
			"hook", "create-container",
			"start-time", getTime(),
		)
		err, annotations := createContainerHook(log)
		if err != nil {
			if shouldFail := checkFail(log, failTestProg, annotations); shouldFail != nil {
				log.Warn("failing container", "error", shouldFail)
				os.Exit(1)
			}
		}
	case "createRuntime":
		// do nothing
	case "poststop":
		// do nothing
	default:
		log.Warn("hook called with unknown hook",
			"hook", cliConf.HookName,
		)
	}

	return
}

func getBinaryDir() string {
	p, err := os.Executable()
	if err != nil {
		// if there is an error, use cwd
		return "."
	}

	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		// if there is an error, use cwd
		return "."
	}

	return path.Dir(p)
}
