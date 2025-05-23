// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package version keeps track of the Kubernetes version the client is
// connected to
package version

import (
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/versioncheck"

	semver "github.com/blang/semver/v4"
	"k8s.io/client-go/kubernetes"
)

// ServerCapabilities is a list of server capabilities derived based on
// version, the Kubernetes discovery API, or probing of individual API
// endpoints.
type ServerCapabilities struct {
	// MinimalVersionMet is true when the minimal version of Kubernetes
	// required to run Cilium has been met
	MinimalVersionMet bool

	// APIExtensionsV1CRD is set to true when the K8s server supports
	// apiextensions/v1 CRDs. TODO: Add link to docs
	//
	// This capability was introduced in K8s version 1.16, prior to which
	// apiextensions/v1beta1 CRDs were used exclusively.
	APIExtensionsV1CRD bool
}

type cachedVersion struct {
	mutex        sync.RWMutex
	capabilities ServerCapabilities
	version      semver.Version
}

const (
	// MinimalVersionConstraint is the minimal version that Cilium supports to
	// run kubernetes.
	MinimalVersionConstraint = "1.16.0"
)

var (
	cached = cachedVersion{}

	// Constraint to check support for apiextensions/v1 CRD types. Support for
	// v1 CRDs was introduced in K8s version 1.16.
	isGEThanAPIExtensionsV1CRD = versioncheck.MustCompile(">=1.16.0")

	// isGEThanMinimalVersionConstraint is the minimal version required to run
	// Cilium
	isGEThanMinimalVersionConstraint = versioncheck.MustCompile(">=" + MinimalVersionConstraint)
)

// Version returns the version of the Kubernetes apiserver
func Version() semver.Version {
	cached.mutex.RLock()
	c := cached.version
	cached.mutex.RUnlock()
	return c
}

// Capabilities returns the capabilities of the Kubernetes apiserver
func Capabilities() ServerCapabilities {
	cached.mutex.RLock()
	c := cached.capabilities
	cached.mutex.RUnlock()
	return c
}

func updateVersion(version semver.Version) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.version = version

	cached.capabilities.MinimalVersionMet = isGEThanMinimalVersionConstraint(version)
	cached.capabilities.APIExtensionsV1CRD = isGEThanAPIExtensionsV1CRD(version)
}

// Force forces the use of a specific version
func Force(version string) error {
	ver, err := versioncheck.Version(version)
	if err != nil {
		return err
	}
	updateVersion(ver)
	return nil
}

func UpdateK8sServerVersion(client kubernetes.Interface) error {
	var ver semver.Version

	sv, err := client.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	// Try GitVersion first. In case of error fallback to MajorMinor
	if sv.GitVersion != "" {
		// This is a string like "v1.9.0"
		ver, err = versioncheck.Version(sv.GitVersion)
		if err == nil {
			updateVersion(ver)
			return nil
		}
	}

	if sv.Major != "" && sv.Minor != "" {
		ver, err = versioncheck.Version(fmt.Sprintf("%s.%s", sv.Major, sv.Minor))
		if err == nil {
			updateVersion(ver)
			return nil
		}
	}

	return fmt.Errorf("cannot parse k8s server version from %+v: %s", sv, err)
}
