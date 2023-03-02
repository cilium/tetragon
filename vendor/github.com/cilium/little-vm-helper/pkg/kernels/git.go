// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/logcmd"

	"github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"
)

type gitCloneOrFetchDirArg struct {
	dir          string
	remoteRepo   string
	remoteBranch string
	depth        int
}

func gitCloneOrFetchDir(ctx context.Context, log logrus.FieldLogger, arg *gitCloneOrFetchDirArg) error {

	var args []string
	if exists, err := directoryExists(arg.dir); err != nil {
		return err
	} else if exists {
		oldPath, err := os.Getwd()
		if err != nil {
			return err
		}
		err = os.Chdir(arg.dir)
		if err != nil {
			return err
		}
		defer os.Chdir(oldPath)
		args = []string{
			"fetch",
		}
	} else {
		args = []string{
			"clone",
			"--depth", fmt.Sprintf("%d", arg.depth),
			"--branch", arg.remoteBranch,
			arg.remoteRepo,
			arg.dir,
		}

	}

	return logcmd.RunAndLogCommandContext(ctx, log, GitBinary, args...)
}

type gitAddWorkdirArg struct {
	workDir      string
	bareDir      string
	remoteName   string
	remoteRepo   string
	remoteBranch string
	localBranch  string
}

func gitAddWorkdir(ctx context.Context, log logrus.FieldLogger, arg *gitAddWorkdirArg) error {
	remoteAddArgs := []string{
		"--git-dir", arg.bareDir,
		"remote", "add",
		"-f", "-t", arg.remoteBranch, arg.remoteName, arg.remoteRepo,
	}
	if err := logcmd.RunAndLogCommandContext(ctx, log, GitBinary, remoteAddArgs...); err != nil {
		return err
	}

	worktreeAddArgs := []string{
		"--git-dir", arg.bareDir,
		"worktree", "add",
		"-b", arg.localBranch,
		"--track",
		arg.workDir,
		fmt.Sprintf("%s/%s", arg.remoteName, arg.remoteBranch),
	}

	return logcmd.RunAndLogCommandContext(ctx, log, GitBinary, worktreeAddArgs...)
}

func gitLocalBranch(kname string) string {
	return fmt.Sprintf("lvh-%s", kname)
}

func removeGitWorkDir(ctx context.Context, log logrus.FieldLogger, dir, kName string) error {
	return gitRemoveWorkdir(context.Background(), log,
		&gitRemoveWorkdirArg{
			workDir:     kName,
			bareDir:     filepath.Join(dir, MainGitDir),
			remoteName:  kName,
			localBranch: gitLocalBranch(kName),
		},
	)
}

type gitRemoveWorkdirArg struct {
	workDir     string
	bareDir     string
	remoteName  string
	localBranch string
}

func gitRemoveWorkdir(ctx context.Context, log logrus.FieldLogger, arg *gitRemoveWorkdirArg) error {
	var res error

	worktreeRemoveArgs := []string{
		"--git-dir", arg.bareDir,
		"worktree", "remove",
		arg.workDir,
	}
	if err := logcmd.RunAndLogCommandContext(ctx, log, GitBinary, worktreeRemoveArgs...); err != nil {
		multierror.Append(res, fmt.Errorf("did not remove worktree: %w", err))
	}

	remoteRemoveArgs := []string{
		"--git-dir", arg.bareDir,
		"remote", "remove",
		arg.remoteName,
	}
	if err := logcmd.RunAndLogCommandContext(ctx, log, GitBinary, remoteRemoveArgs...); err != nil {
		multierror.Append(res, fmt.Errorf("did not remove remote: %w", err))
	}

	branchRemoveArgs := []string{
		"--git-dir", arg.bareDir,
		"branch", "--delete", "--force",
		arg.localBranch,
	}
	if err := logcmd.RunAndLogCommandContext(ctx, log, GitBinary, branchRemoveArgs...); err != nil {
		multierror.Append(res, fmt.Errorf("did not remove local branch: %w", err))
	}

	return res
}
