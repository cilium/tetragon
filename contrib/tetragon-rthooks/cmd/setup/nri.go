// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package main

import (
	"context"
	"log/slog"
	"os"
	"path"
	"path/filepath"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type plugin struct {
	stub stub.Stub
	log  *slog.Logger
	conf *Install
}

func (p *plugin) CreateContainer(
	_ context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	binBaseName := path.Base(p.conf.LocalBinary)

	binFname := filepath.Join(p.conf.HostInstallDir, binBaseName)
	logFname := filepath.Join(p.conf.HostInstallDir, logBaseName)

	getArgs := func(stage string) []string {
		args := []string{binBaseName, stage, "--log-fname", logFname}
		args = append(args, p.conf.HookArgs.Args...)
		return args
	}

	adjust := &api.ContainerAdjustment{}
	hooks := api.Hooks{
		CreateRuntime: []*api.Hook{
			&api.Hook{
				Path:    binFname,
				Args:    getArgs("createRuntime"),
				Env:     nil,
				Timeout: nil,
			},
		},
	}
	adjust.AddHooks(&hooks)
	p.log.Info("Added tetragon-oci-hook to container", "name", container.Name, "id", container.Id)
	return adjust, nil, nil
}

func (i *Install) nriHookStart(log *slog.Logger) {
	if !i.Daemonize {
		log.Error("NRI hook setup needs to be daemonized")
		os.Exit(1)
	}

	// copy the binary to the host
	i.copyBinary(log)

	p := &plugin{
		log:  log,
		conf: i,
	}
	opts := []stub.Option{
		stub.WithPluginName(i.NriHook.Name),
		stub.WithPluginIdx(i.NriHook.Index),
	}
	var err error
	if p.stub, err = stub.New(p, opts...); err != nil {
		log.Error("failed to create plugin stub", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	err = p.stub.Run(ctx)
	if err != nil {
		log.Error("plugin exited with error", "error", err)
		os.Exit(1)
	}
}
