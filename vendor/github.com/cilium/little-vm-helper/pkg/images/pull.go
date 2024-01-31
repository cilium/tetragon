// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/moby/term"
)

type PullConf struct {
	Image     string
	TargetDir string
	Cache     bool
}

type ExtractResult struct {
	Images []string
}

// PullImage pulls an OCI image from a remote repository and decompresses it
// into a local directory.
func PullImage(ctx context.Context, conf PullConf) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("cannot establish client for image %s: %w", conf.Image, err)
	}
	defer cli.Close()

	remotePullReader, err := cli.ImagePull(ctx, conf.Image, types.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("cannot pull image %s: %w", conf.Image, err)
	}
	defer remotePullReader.Close()

	// Complete the image pull, and pretty print while we're at it.
	fd, isTerm := term.GetFdInfo(os.Stderr)
	if err = jsonmessage.DisplayJSONMessagesStream(remotePullReader, os.Stderr, fd, isTerm, nil); err != nil {
		return fmt.Errorf("image pull unexpectedly terminated: %w", err)
	}
	return nil
}

func ExtractImage(ctx context.Context, conf PullConf) (*ExtractResult, error) {
	result := &ExtractResult{
		Images: make([]string, 0, 1),
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("cannot establish client for image %s: %w", conf.Image, err)
	}
	defer cli.Close()

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: conf.Image,
		Tty:   false,
	}, nil, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("cannot create container from %s: %w", conf.Image, err)
	}
	defer func() {
		err := cli.ContainerRemove(ctx, resp.ID, types.ContainerRemoveOptions{
			Force: true,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not clean up container %s: %s\n", resp.ID, err)
		}
	}()

	ctrImagesPath := filepath.Join("/", "data", "images")
	imageReader, _, err := cli.CopyFromContainer(ctx, resp.ID, ctrImagesPath)
	if err != nil {
		return nil, fmt.Errorf("unable to locate images inside %s: %w", conf.Image, err)
	}
	defer imageReader.Close()

	tarReader := tar.NewReader(imageReader)
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header in %s: %w", conf.Image, err)
		}

		image, err := handleTarObject(ctx, tarReader, hdr, conf, resp.ID)
		if image != "" {
			result.Images = append(result.Images, image)
		}
		if err != nil {
			return result, err
		}
	}

	return result, nil
}

func handleTarObject(ctx context.Context, tr *tar.Reader, hdr *tar.Header, conf PullConf, containerID string) (string, error) {
	image := ""

	dstPath := filepath.Join(conf.TargetDir, hdr.Name)
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(dstPath, 0755); err != nil {
			return image, fmt.Errorf("failed to create directory %s: %w", dstPath, err)
		}
	case tar.TypeReg:
		compressed := strings.HasSuffix(dstPath, ".zst")
		if compressed {
			image = strings.TrimSuffix(dstPath, ".zst")
			if _, err := os.Stat(image); err == nil {
				return image, os.ErrExist
			}

			cmd := exec.CommandContext(ctx, "zstd", "-d", "-", "-o", image)
			cmd.Stdin = tr

			if _, err := cmd.Output(); err != nil {
				var e *exec.ExitError
				if errors.As(err, &e) {
					fmt.Fprintf(os.Stderr, string(e.Stderr))
				}
				return image, fmt.Errorf("failed during zst decompression of %s: %w", hdr.Name, err)
			}
		}
		if conf.Cache || !compressed {
			dst, err := os.Create(dstPath)
			if err != nil {
				return image, fmt.Errorf("failed to create file %s: %w", dstPath, err)
			}
			defer dst.Close()

			n, err := io.CopyN(dst, tr, hdr.Size)
			if err != nil {
				return image, fmt.Errorf("failed to copy %s from container %s: %w", dstPath, containerID, err)
			}
			if n != hdr.Size {
				return image, fmt.Errorf("tar header reports file %s size %d, but only %d bytes were pulled", hdr.Name, hdr.Size, n)
			}
		}
	default:
		return image, fmt.Errorf("unexpected tar header type %d", hdr.Typeflag)
	}

	return image, nil
}
