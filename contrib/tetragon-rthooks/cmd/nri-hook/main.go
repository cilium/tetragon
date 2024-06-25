// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// inspired by https://github.com/containerd/nri/blob/main/plugins/hook-injector/hook-injector.go

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type plugin struct {
	stub stub.Stub
	conf *Cli
}

type Cli struct {
	LogLevel    string `name:"log-level" default:"info" help:"log level"`
	OCIHookPath string `name:"oci-hook-path" help:"OCI hook path" default:"/opt/tetragon/tetragon-oci-hook"`
	NriIndex    string `name:"nri-index" default:"01" help:"NRI index number"`
}

func (p *plugin) CreateContainer(
	_ context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	adjust := &api.ContainerAdjustment{}
	arg0 := filepath.Base(p.conf.OCIHookPath)
	hooks := api.Hooks{
		CreateRuntime: []*api.Hook{
			&api.Hook{
				Path:    p.conf.OCIHookPath,
				Args:    []string{arg0, "createRuntime"},
				Env:     nil,
				Timeout: nil,
			},
		},
		CreateContainer: []*api.Hook{
			&api.Hook{
				Path:    p.conf.OCIHookPath,
				Args:    []string{arg0, "createContainer"},
				Env:     nil,
				Timeout: nil,
			},
		},
	}
	adjust.AddHooks(&hooks)
	return adjust, nil, nil
}

func (c *Cli) Run(log *slog.Logger) error {
	p := &plugin{
		conf: c,
	}
	opts := []stub.Option{
		stub.WithPluginName("tetragon"),
		stub.WithPluginIdx(c.NriIndex),
	}
	var err error
	if p.stub, err = stub.New(p, opts...); err != nil {
		log.Error("failed to create plugin stub", "error", err)
		return err
	}

	ctx := context.Background()
	err = p.stub.Run(ctx)
	if err != nil {
		log.Error("plugin exited with error", "error", err)
	}
	return err
}

func main() {

	var cli Cli
	ctx := kong.Parse(&cli)

	if kongCmd := ctx.Command(); kongCmd != "" {
		fmt.Fprintf(os.Stderr, "unexpected parsing result: %s", kongCmd)
		os.Exit(1)
	}

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(cli.LogLevel)); err != nil {
		slog.Error("failed to parse log level", "level", cli.LogLevel, "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	err := ctx.Run(logger)
	ctx.FatalIfErrorf(err)
}
