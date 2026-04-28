/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/vladimirvivien/gexe"
	log "k8s.io/klog/v2"
)

type Opts struct {
	// Name is used to indicate the name of the helm chart being processed
	Name string
	// Namespace is used to indicate the namespace in which the helm chart
	// identified by Name will be processed
	Namespace string
	// ReleaseName is used to indicate the name of the release to be used
	// while installing or upgrading the chart identified by Name into the
	// Namespace
	ReleaseName string
	// Version is the helm chart version that should be deployed to the test
	// infrastructure
	Version string
	// Chart is used to indicate the full path of the .tgz artifact of the Helm
	// chart in case if your tests require you to be able to deploy a packaged
	// helm chart that is available locally as the tarball
	Chart string
	// mode is used to indicate the mode in which the helm operation is being
	// performed. These are the first level commands that are processed by the
	// helm Binary
	mode string
	// Args is used to pass any additional arguments that you might want to pass
	// for running the helm command in question
	Args []string
	// Wait is used to indicate if the helm command should wait for the runtime
	// to reach an acceptable state before returning the control back. The duration
	// for which this call is blocked is defined by the value set to Timeout
	Wait bool
	// Timeout is used to indicate the time to wait for any individual Kubernetes ops
	Timeout string
}

type Manager struct {
	e          *gexe.Echo
	kubeConfig string
	path       string
}

type Option func(*Opts)

const (
	missingHelm = "'helm' command is missing. Please ensure the tool exists before using the helm manager"
)

// WithName is used to set the name of the helm chart being processed
func WithName(name string) Option {
	return func(opts *Opts) {
		opts.Name = name
	}
}

// WithNamespace is used to configure the namespace in which the helm chart
// identified by WithName will be processed
func WithNamespace(namespace string) Option {
	return func(opts *Opts) {
		opts.Namespace = namespace
	}
}

// WithReleaseName is used to configure the name of the release to be used
// while installing or upgrading the chart identified by WithName into the
// WithNamespace configured namespace
func WithReleaseName(releaseName string) Option {
	return func(opts *Opts) {
		opts.ReleaseName = releaseName
	}
}

// WithVersion is used to configre helm chart version that should be deployed
// to the test infrastructure
func WithVersion(version string) Option {
	return func(opts *Opts) {
		opts.Version = version
	}
}

// WithChart is used to configure the full path of the .tgz artifact of the Helm
// chart in case if your tests require you to be able to deploy a packaged
// helm chart that is available locally as the tarball
func WithChart(chart string) Option {
	return func(opts *Opts) {
		opts.Chart = chart
	}
}

// WithArgs is used to inject additional arguments into the Helm commands.
// Please pay careful consideration while using this as the current one
// does not have the ability to de-dup the arguments since options such as
// -f or --set can be used multiple times with different values, and we wanted
// the end user to make the decision of how the commands are invoked and not
// restrict them to a specific way of invoking the commands.
func WithArgs(args ...string) Option {
	return func(opts *Opts) {
		opts.Args = append(opts.Args, args...)
	}
}

// WithWait is used to configure the argument used by the helm to indicate it
// should wait for an acceptable state of the resource before yielding the
// control back to the invocation point
func WithWait() Option {
	return func(opts *Opts) {
		opts.Wait = true
	}
}

// WithTimeout is used to configure the time for which the helm command should
// be in blocked wait mode for the acceptable state of the resource to be reached
func WithTimeout(timeout string) Option {
	return func(opts *Opts) {
		opts.Timeout = timeout
	}
}

// processOpts is used to generate the Opts resource that will be used to generate
// the actual helm command to be run using the getCommand helper
func (m *Manager) processOpts(opts ...Option) *Opts {
	option := &Opts{}
	for _, op := range opts {
		op(option)
	}
	return option
}

// getCommand is used to convert the Opts into a helm suitable command to be run
func (m *Manager) getCommand(opt *Opts) (string, error) {
	commandParts := []string{m.path, opt.mode}
	if opt.mode == "" {
		return "", fmt.Errorf("missing helm operation mode. Please use the WithMode option while invoking the run")
	}
	if opt.Name != "" {
		commandParts = append(commandParts, opt.Name)
	}
	if opt.Chart != "" {
		commandParts = append(commandParts, opt.Chart)
	} else {
		commandParts = append(commandParts, opt.ReleaseName)
	}
	if opt.Namespace != "" {
		commandParts = append(commandParts, "--namespace", opt.Namespace)
	}
	if opt.Version != "" {
		commandParts = append(commandParts, "--version", opt.Version)
	}
	commandParts = append(commandParts, opt.Args...)
	if opt.Wait {
		commandParts = append(commandParts, "--wait")
	}
	if opt.Timeout != "" {
		commandParts = append(commandParts, "--timeout", opt.Timeout)
	}
	commandParts = append(commandParts, "--kubeconfig", m.kubeConfig)
	return strings.Join(commandParts, " "), nil
}

// RunRepo provides a way to run `helm repo` sub command hierarchies using the right
// combination of WithArgs to build the suitable repo management sub command structure.
func (m *Manager) RunRepo(opts ...Option) error {
	o := m.processOpts(opts...)
	o.mode = "repo"
	return m.run(o)
}

// RunInstall provides a way to install the helm chart either from the local path or
// using the configured helm repository with a specific chart name.
func (m *Manager) RunInstall(opts ...Option) error {
	o := m.processOpts(opts...)
	o.mode = "install"
	return m.run(o)
}

// RunUninstall provides a way to uninstall the specified helm chart (useful in teardowns etc...)
func (m *Manager) RunUninstall(opts ...Option) error {
	o := m.processOpts(opts...)
	o.mode = "uninstall"
	return m.run(o)
}

// RunTemplate provides a way to invoke the `helm template` commands that can be used
// to perform the basic sanity check on the charts to make sure if the charts can be
// rendered successfully or not.
func (m *Manager) RunTemplate(opts ...Option) error {
	o := m.processOpts(opts...)
	o.mode = "template"
	return m.run(o)
}

// RunUpgrade provides a way to invoke the `helm upgrade` sub commands that can be
// used to perform the chart upgrade operation tests. This can be combined with suitable
// arguments to even install the charts if they are not already existing in the cluster.
func (m *Manager) RunUpgrade(opts ...Option) error {
	o := m.processOpts(opts...)
	o.mode = "upgrade"
	return m.run(o)
}

// RunTest provides a way to perform the `helm test` sub command that can be leveraged
// to perform a test using the helm infra on the deployed charts.
func (m *Manager) RunTest(opts ...Option) error {
	o := m.processOpts(opts...)
	o.mode = "test"
	return m.run(o)
}

// run method is used to invoke a helm command to perform a suitable operation.
// Please make sure to configure the right Opts using the Option helpers
func (m *Manager) run(opts *Opts) (err error) {
	if m.path == "" {
		m.path = "helm"
	}
	log.V(4).InfoS("Determining if helm binary is available or not", "executable", m.path)
	if m.e.Prog().Avail(m.path) == "" {
		err = errors.New(missingHelm)
		return
	}
	command, err := m.getCommand(opts)
	if err != nil {
		return
	}
	log.V(4).InfoS("Running Helm Operation", "command", command)
	proc := m.e.NewProc(command)

	var stderr bytes.Buffer
	proc.SetStderr(&stderr)

	result := proc.Run().Result()
	log.V(4).Info("Helm Command output \n", result)
	if !proc.IsSuccess() {
		return fmt.Errorf("%s: %w", strings.TrimSuffix(stderr.String(), "\n"), proc.Err())
	}
	return nil
}

// WithPath is used to provide a custom path where the `helm` executable command
// can be found. This is useful in case if your binary is in a non standard location
// and you want to framework to use that instead of returning an error.
func (m *Manager) WithPath(path string) *Manager {
	m.path = path
	return m
}

func New(kubeConfig string) *Manager {
	return &Manager{e: gexe.New(), kubeConfig: kubeConfig}
}
