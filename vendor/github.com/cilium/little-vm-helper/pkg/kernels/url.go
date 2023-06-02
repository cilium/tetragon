// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"context"
	"fmt"
	"net/url"

	"github.com/sirupsen/logrus"
)

type KernelURL interface {
	// fetches the kernel named <name> in <dir>/<name>
	fetch(ctx context.Context, log logrus.FieldLogger, dir string, name string) error
	// removes the kernel named <name>
	remove(ctx context.Context, log logrus.FieldLogger, dir string, name string) error
}

func ParseURL(s string) (KernelURL, error) {

	kurl, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	switch kurl.Scheme {
	case "git", "https":
		return NewGitURL(kurl)

	// NB: there are also git repos using http so we would need
	// some detection based on the suffix, e.g., .git vs .tgz
	case "http":
		return nil, fmt.Errorf("%s support coming soon!", kurl.Scheme)

	default:
		return nil, fmt.Errorf("Unsupported URL: '%s'", kurl)
	}

}
