// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"fmt"
	"strings"
)

type UrlExample struct {
	Name string
	URL  string

	// NB: used for testing
	expectedKernelURL KernelURL
}

var UrlExamples = []UrlExample{
	{
		Name: "bpf-next",
		URL:  "git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git",
		expectedKernelURL: &GitURL{
			Repo:         "git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git",
			Branch:       "master",
			ShallowDepth: -1,
		},
	}, {
		Name: "5.18",
		URL:  "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git#linux-5.18.y",
		expectedKernelURL: &GitURL{
			Repo:         "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
			Branch:       "linux-5.18.y",
			ShallowDepth: -1,
		},
	}, {
		Name: "5.15",
		URL:  "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git?depth=1#linux-5.15.y",
		expectedKernelURL: &GitURL{
			Repo:         "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
			Branch:       "linux-5.15.y",
			ShallowDepth: 1,
		},
	},
}

func GetExamplesText() string {
	var sb strings.Builder

	for _, ex := range UrlExamples {
		sb.WriteString(fmt.Sprintf("  add %s %s\n", ex.Name, ex.URL))
	}

	sb.WriteString("\n")
	sb.WriteString("The bpf-next and 5.18 kernels will use a common bare repository and git worktrees.\nThe 5.15 kernel will be cloned in a shallow dir on its own.")

	return sb.String()
}
