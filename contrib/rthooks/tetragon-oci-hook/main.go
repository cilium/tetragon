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
	"syscall"
	"time"

	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	logfname     = "/var/log/tetragon-oci-hook.log"
	agentAddress = "unix:///var/run/cilium/tetragon/tetragon.sock"
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

	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	conn, err := grpc.DialContext(connCtx, agentAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("connecting to agent (%s) failed: %s", err, agentAddress)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	_, err = client.RuntimeHook(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func createContainerHook(log_ *logrus.Logger) {
	log := log_.WithField("hook", "create-container").WithField("start-time", getTime())

	// rootDir is the current directory
	rootDir, err := os.Getwd()
	var configName string
	if err != nil {
		log.Warnf("failed to retrieve CWD: %s", err)
		configName = "./../config.json"
	} else {
		// Use full path for config.json for better log messages
		configName = filepath.Join(rootDir, "..", "config.json")
	}

	// We use the cgroup name to determine the containerID
	// We use the config.json file to get the cgroup name. (We could have used /proc/self/cgroup, but it's more complicated.)
	var cgroupPath string
	spec, err := readJsonSpec(configName)
	if err != nil {
		log.WithError(err).Warnf("failed to read spec file: %s", configName)
	} else if spec.Linux == nil {
		log.Warnf("unexpected error: Linux is empty on spec %+v", spec)
	} else {
		cgroupPath = spec.Linux.CgroupsPath
	}

	// if have no information whatsover, do not contact the agent
	if cgroupPath == "" && rootDir == "" {
		log.Warn("unable to determine either RootDir or cgroupPath, bailing out")
		return
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

	err = hookRequest(req)
	if err != nil {
		log.WithError(err).WithField("req", req).Warn("hook request to agent failed")
	} else {
		log.WithField("req", req).Info("hook request to agent succeeded")
	}
}

func main() {
	log := logrus.New()
	log.SetOutput(&lumberjack.Logger{
		Filename:   logfname,
		MaxSize:    50, // megabytes
		MaxBackups: 3,
		MaxAge:     7, //days
	})

	if len(os.Args) < 2 {
		log.Warn("hook called without arguments, bailing out")
		return
	}

	hookName := os.Args[1]
	switch hookName {
	case "createContainer":
		createContainerHook(log)
	case "createRuntime":
		// do nothing
	case "poststop":
		// do nothing
	default:
		log.WithField("hook", hookName).Warn("hook called with unknown hook")
	}

	return
}
