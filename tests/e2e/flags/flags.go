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
		BTF:              "",
		HelmValues: HelmValues{
			// Don't stop any events from being exported by default
			"tetragon.exportAllowList": "",
		},
	},
	KeepExportData: false,
	InstallCilium:  true,
	// renovate: datasource=go depName=github.com/cilium/cilium
	CiliumVersion: "v1.17.1",
}

func init() {
	flag.BoolVar(&Opts.Helm.Wait,
		"tetragon.helm.wait",
		Opts.Helm.Wait,
		"Set to true if we should wait for Tetragon to be installed before starting the test")

	flag.StringVar(&Opts.Helm.DaemonSetName,
		"tetragon.helm.daemonset",
		Opts.Helm.DaemonSetName,
		"Name for the Tetragon daemonset + install target")

	flag.StringVar(&Opts.Helm.HelmChart,
		"tetragon.helm.chart",
		Opts.Helm.HelmChart,
		"Name of the helm chart from which to install Tetragon")

	flag.StringVar(&Opts.Helm.HelmRepoUrl,
		"tetragon.helm.url",
		Opts.Helm.HelmRepoUrl,
		"Name of the helm repo where we find Tetragon")

	flag.StringVar(&Opts.Helm.HelmChartVersion,
		"tetragon.helm.version",
		Opts.Helm.HelmChartVersion,
		"Helm chart version to use")

	flag.StringVar(&Opts.Helm.Namespace,
		"tetragon.helm.namespace",
		Opts.Helm.Namespace,
		"Namespace in which to install Tetragon")

	flag.StringVar(&Opts.Helm.ValuesFile,
		"tetragon.helm.values",
		Opts.Helm.ValuesFile,
		"Path to a values.yaml file")

	flag.Var(&Opts.Helm.HelmValues,
		"tetragon.helm.set",
		"Values to pass directly to helm, of the form k=v")

	flag.BoolVar(&Opts.KeepExportData,
		"tetragon.keep-export",
		Opts.KeepExportData,
		"Should we keep export files regardless of pass/fail?")

	flag.BoolVar(&Opts.InstallCilium,
		"tetragon.install-cilium",
		Opts.InstallCilium,
		"Should we install Cilium in the test?")

	flag.StringVar(&Opts.Helm.BTF,
		"tetragon.btf",
		Opts.Helm.BTF,
		"A BTF file on the host that should be loaded into the KinD cluster. Will override helm BTF settings. Only makes sense when testing on a KinD cluster.")

	flag.StringVar(&Opts.CiliumVersion,
		"tetragon.cilium-version",
		Opts.CiliumVersion,
		"Version of Cilium to install. Only makes sense if tetragon.install-cilium is true.")
}

type Flags struct {
	Helm HelmOptions
	// Should we keep the export file for the tests regardless of pass/fail?
	KeepExportData bool
	// Should we install Cilium in the test?
	InstallCilium bool
	// Version of Cilium to use
	CiliumVersion string
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
	// BTF file to load into the kind cluster
	BTF string
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
