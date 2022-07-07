// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package flags

import (
	"flag"
	"fmt"
	"strings"
)

var Opts = Flags{
	Helm: HelmOptions{
		Wait:             true,
		DaemonSetName:    "tetragon",
		HelmChart:        "cilium/tetragon",
		HelmRepoUrl:      "https://helm.cilium.io",
		HelmChartVersion: "9999.9999.9999-dev",
		Namespace:        "kube-system",
		ValuesFile:       "",
		HelmValues: HelmValues{
			// Don't stop any events from being exported by default
			"tetragon.exportAllowList": "",
		},
	},
	KeepExportData: false,
	InstallCilium:  true,
}

func init() {
	flag.BoolVar(&Opts.Helm.Wait,
		"tetragon.helm.wait",
		Opts.Helm.Wait,
		"set to true if we should wait for Tetragon to be installed before starting the test")

	flag.StringVar(&Opts.Helm.DaemonSetName,
		"tetragon.helm.daemonset",
		Opts.Helm.DaemonSetName,
		"name for the Tetragon daemonset + install target")

	flag.StringVar(&Opts.Helm.HelmChart,
		"tetragon.helm.chart",
		Opts.Helm.HelmChart,
		"name of the helm chart from which to install Tetragon")

	flag.StringVar(&Opts.Helm.HelmRepoUrl,
		"tetragon.helm.url",
		Opts.Helm.HelmRepoUrl,
		"name of the helm repo where we find Tetragon")

	flag.StringVar(&Opts.Helm.HelmChartVersion,
		"tetragon.helm.version",
		Opts.Helm.HelmChartVersion,
		"helm chart version to use")

	flag.StringVar(&Opts.Helm.Namespace,
		"tetragon.helm.namespace",
		Opts.Helm.Namespace,
		"namespace in which to install Tetragon")

	flag.StringVar(&Opts.Helm.ValuesFile,
		"tetragon.helm.values",
		Opts.Helm.ValuesFile,
		"path to a values.yaml file")

	flag.Var(&Opts.Helm.HelmValues,
		"tetragon.helm.set",
		"values to pass directly to helm, of the form k=v")

	flag.BoolVar(&Opts.KeepExportData,
		"tetragon.keep-export",
		Opts.KeepExportData,
		"should we keep export files regardless of pass/fail?")

	flag.BoolVar(&Opts.InstallCilium,
		"tetragon.install-cilium",
		Opts.InstallCilium,
		"should we install Cilium in the test?")
}

type Flags struct {
	Helm HelmOptions
	// Should we keep the export file for the tests regardless of pass/fail?
	KeepExportData bool
	// Should we install Cilium in the test?
	InstallCilium bool
}

type HelmOptions struct {
	// Should helm wait for deployment to be ready?
	Wait bool
	// Name of the daemonset
	DaemonSetName string
	// Name of the helm chart
	HelmChart string
	// Url of the helm repo
	HelmRepoUrl string
	// Version of the helm chart
	HelmChartVersion string
	// Namespace to install Tetragon
	Namespace string
	// Optional values.yaml file for the Tetragon chart
	ValuesFile string
	// Optional helm values (a map specifying values to set)
	HelmValues
}

type HelmValues map[string]string

func (h *HelmValues) String() string {
	var vals strings.Builder
	for k, v := range *h {
		vals.WriteString(fmt.Sprintf("%s=\"%s\", ", k, v))
	}
	return fmt.Sprintf("HelmOptions(%s)", strings.TrimSuffix(vals.String(), ", "))
}

func (h *HelmValues) Set(value string) error {
	if *h == nil {
		*h = make(map[string]string)
	}
	kvs := strings.SplitN(value, "=", 2)
	if len(kvs) != 2 {
		return fmt.Errorf("helm options must be of the form k=v, got `%s`", value)
	}
	(*h)[kvs[0]] = kvs[1]
	return nil
}
