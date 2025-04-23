// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cilium

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

type Opts struct {
	Wait           bool
	Namespace      string
	Version        string
	ChartDirectory string
	HelmOptions    map[string]string
}

type Option func(*Opts)

func WithWait(wait bool) Option {
	return func(o *Opts) { o.Wait = wait }
}

func WithNamespace(namespace string) Option {
	return func(o *Opts) { o.Namespace = namespace }
}

func WithVersion(version string) Option {
	return func(o *Opts) { o.Version = version }
}

func WithChartDirectory(chartDirectory string) Option {
	return func(o *Opts) { o.ChartDirectory = chartDirectory }
}

func WithHelmOptions(helmOptions map[string]string) Option {
	return func(o *Opts) {
		// TODO: copy instead?
		o.HelmOptions = helmOptions
	}
}

func processOpts(opts ...Option) *Opts {
	o := &Opts{}
	for _, op := range opts {
		op(o)
	}
	return o
}

type ciliumCLI struct {
	cmd  string
	opts *Opts
}

func newCiliumCLI(opts *Opts) *ciliumCLI {
	return &ciliumCLI{
		cmd:  "cilium",
		opts: opts,
	}
}

func (c *ciliumCLI) findOrInstall() error {
	if _, err := exec.LookPath(c.cmd); err != nil {
		// TODO: try to install cilium-cli using `go install` or similar
		return fmt.Errorf("cilium: cilium-cli not installed or could not be found: %w", err)
	}

	ver, err := exec.Command(c.cmd, "version").Output()
	if err != nil {
		return fmt.Errorf("cilium: could not execute cilium version: %w", err)
	}
	v := bytes.Split(ver, []byte("\n"))
	if len(v) > 0 {
		klog.Infof("Found cilium-cli version %s", v[0])
	}

	// TODO: check against expected cilium-cli version?

	return nil
}

func (c *ciliumCLI) install() error {
	if err := c.findOrInstall(); err != nil {
		return err
	}

	// TODO: determine status of potential previous installation using `cilium status`,
	// e.g. by introducing a `cilium status --brief` flag reporting ready/not ready.

	// Uninstall pre-existing Cilium installation.
	_ = c.uninstall()

	args := []string{"install"}
	if c.opts.Wait {
		args = append(args, "--wait")
	}
	if c.opts.Namespace != "" {
		args = append(args, "--namespace="+c.opts.Namespace)
	}
	if c.opts.ChartDirectory != "" {
		args = append(args, "--chart-directory="+c.opts.ChartDirectory)
	}
	if c.opts.Version != "" {
		args = append(args, "--version="+c.opts.Version)
	}
	for k, v := range c.opts.HelmOptions {
		args = append(args, fmt.Sprintf("--helm-set=%s=%s", k, v))
	}

	installCmd := exec.Command(c.cmd, args...)
	klog.Infof("Running cilium install command %s", installCmd)
	_, err := installCmd.Output()
	if err != nil {
		if exitError := new(exec.ExitError); errors.As(err, &exitError) {
			return fmt.Errorf("cilium install command failed: %s: %s", exitError.String(), exitError.Stderr)
		}
		return fmt.Errorf("cilium install command failed: %w", err)
	}

	c.status(true)

	return nil
}

func (c *ciliumCLI) uninstall() error {
	if err := c.findOrInstall(); err != nil {
		return err
	}

	args := []string{"uninstall"}
	if c.opts.ChartDirectory != "" {
		args = append(args, "--chart-directory="+c.opts.ChartDirectory)
	}

	uninstallCmd := exec.Command(c.cmd, args...)
	klog.Infof("Running cilium uninstall command %s", uninstallCmd)
	_, err := uninstallCmd.Output()
	if err != nil {
		if exitError := new(exec.ExitError); errors.As(err, &exitError) {
			return fmt.Errorf("cilium uninstall command failed: %s: %s", exitError.String(), exitError.Stderr)
		}
		return fmt.Errorf("cilium uninstall command failed: %w", err)
	}

	return nil
}

func (c *ciliumCLI) status(wait bool) error {
	if err := c.findOrInstall(); err != nil {
		return err
	}

	args := []string{"status"}
	if wait {
		args = append(args, "--wait")
	}
	statusCmd := exec.Command(c.cmd, args...)
	klog.Infof("Running cilium status command %s", statusCmd)
	stdout, err := statusCmd.Output()
	if err != nil {
		if exitError := new(exec.ExitError); errors.As(err, &exitError) {
			return fmt.Errorf("cilium status command failed: %s: %s", exitError.String(), exitError.Stderr)
		}
		return fmt.Errorf("cilium status command failed: %w", err)
	}

	klog.Infof("Cilium status\n%s", stdout)

	return nil
}

// Setup installs Cilium with the given options.
func Setup(options ...Option) env.Func {
	o := processOpts(options...)
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		return ctx, newCiliumCLI(o).install()
	}
}

// Finish uninstalls Cilium.
func Finish(options ...Option) env.Func {
	o := processOpts(options...)
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		return ctx, newCiliumCLI(o).uninstall()
	}
}
