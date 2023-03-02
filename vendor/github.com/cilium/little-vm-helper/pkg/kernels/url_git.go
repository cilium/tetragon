// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/cilium/little-vm-helper/pkg/logcmd"
	"github.com/sirupsen/logrus"
)

// By default, we use a single directory (MainGitDir) for all git URLs (first
// fetch is slow, but subsequent ones should be fast). Each URL is a different
// remote in this repository using a different name (typically the kernel
// name). (This means that we might end up with the same remote on different
// names, but that's fine.)
//
// There are use-cases, however, where we just want to download the code and
// build it.  For those, we also define shallow repositories that are just
// checked out on their own.
// Shallow repos are defined with a depth=x parameter in the URL.

var MainGitDir = "git"

type GitURL struct {
	Repo string

	// Branch in remote (by default, master)
	Branch string

	// depth for shallow directories (-1 means clone the full repo)
	ShallowDepth int
}

func NewGitURL(kurl *url.URL) (KernelURL, error) {
	// NB: far from perfect, but works for the simple cases
	repo := fmt.Sprintf("%s://%s%s", kurl.Scheme, kurl.Host, kurl.Path)
	// NB: we (ab)use the fragment part of the URL to store the branch
	branch := kurl.Fragment
	url := newGitURL(repo, branch)

	q := kurl.Query()
	if val, ok := q["depth"]; ok {

		if len(val) != 1 {
			return nil, fmt.Errorf("invalid depth value: `%s`", val)
		}

		if d, err := strconv.Atoi(val[0]); err != nil {
			return nil, fmt.Errorf("invalid depth value: `%s`", val[0])
		} else if d < 0 {
			return nil, fmt.Errorf("invalid depth value: `%s`", val[0])
		} else {
			url.ShallowDepth = d
		}
	}

	return url, nil
}

func newGitURL(repo string, branch string) *GitURL {
	if branch == "" {
		branch = "master"
	}

	return &GitURL{
		Repo:         repo,
		Branch:       branch,
		ShallowDepth: -1,
	}
}

func (gu *GitURL) syncWorktree(
	ctx context.Context,
	log logrus.FieldLogger,
	idDir string,
) error {
	oldPath, err := os.Getwd()
	if err != nil {
		return err
	}

	err = os.Chdir(idDir)
	if err != nil {
		return err
	}
	defer os.Chdir(oldPath)

	cmd := exec.CommandContext(ctx, "git", "pull")
	return logcmd.RunAndLogCommand(cmd, log)
}

func makeGitDir(ctx context.Context, log logrus.FieldLogger, gitDir string) error {
	err := os.MkdirAll(gitDir, 0755)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "git", "init", "--bare", gitDir)
	if err := logcmd.RunAndLogCommand(cmd, log); err != nil {
		os.RemoveAll(gitDir)
		return err
	}

	return nil
}

// fetch will fetches the code pointed by gu, into dir/id
func (gu *GitURL) fetch(
	ctx context.Context,
	log logrus.FieldLogger,
	dir string,
	id string,
) error {

	// NB: we should probably moved that elsewhere, e.g., in its own CLI command.
	if err := CheckEnvironment(); err != nil {
		return err
	}

	if id == MainGitDir {
		return fmt.Errorf("id `%s` is not allowed. Please use another.", id)
	}

	// directories are
	// <dir>/<MainGitDir> ->  git repo (used for non-shallow repos)
	// <dir>/<id> -> one worktree or shallow repo per id
	gitDir := filepath.Join(dir, MainGitDir)
	idDir := filepath.Join(dir, id)

	if gu.ShallowDepth != -1 {
		return gitCloneOrFetchDir(ctx, log, &gitCloneOrFetchDirArg{
			dir:          idDir,
			remoteRepo:   gu.Repo,
			remoteBranch: gu.Branch,
			depth:        gu.ShallowDepth,
		})
	}

	if idExists, err := directoryExists(idDir); err != nil {
		return err
	} else if idExists {
		return gu.syncWorktree(ctx, log, idDir)
	}

	if gitExists, err := directoryExists(gitDir); err != nil {
		return err
	} else if !gitExists {
		if err := makeGitDir(ctx, log, gitDir); err != nil {
			return err
		}
	}

	return gitAddWorkdir(ctx, log, &gitAddWorkdirArg{
		workDir:      idDir,
		bareDir:      gitDir,
		remoteName:   id,
		remoteRepo:   gu.Repo,
		remoteBranch: gu.Branch,
		localBranch:  gitLocalBranch(id),
	})
}

func (gu *GitURL) remove(
	ctx context.Context,
	log logrus.FieldLogger,
	dir string,
	id string,
) error {
	if gu.ShallowDepth != -1 {
		idDir := filepath.Join(dir, id)
		return os.RemoveAll(idDir)
	}
	err := removeGitWorkDir(ctx, log, dir, id)
	if err != nil {
		log.WithError(err).Warn("remove work dir encountered errors")
	}
	return err
}
