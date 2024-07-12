// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
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

	remotePullReader, err := cli.ImagePull(ctx, conf.Image, image.PullOptions{})
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
		err := cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{
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

		// Copy the target file out to the host (compressed or not).
		dstFile, err := os.Create(dstPath)
		if err != nil {
			return image, fmt.Errorf("failed to open %s: %w", dstPath, err)
		}
		defer func() {
			path := dstFile.Name()
			dstFile.Close()
			if err != nil || (!conf.Cache && compressed) {
				// Only keep the compressed copy on the hostfs
				// if asked for it, and if there are no errors.
				os.Remove(path)
				return
			}
		}()

		n, err := io.CopyN(dstFile, tr, hdr.Size)
		if err != nil {
			return image, fmt.Errorf("failed to copy %s from container %s: %w", dstPath, containerID, err)
		}
		if n != hdr.Size {
			return image, fmt.Errorf("tar header reports file %s size %d, but only %d bytes were pulled", hdr.Name, hdr.Size, n)
		}

		if compressed {
			if _, err = dstFile.Seek(0, 0); err != nil {
				return image, fmt.Errorf("cannot seek to the start of the compressed target file %s: %w", dstPath, err)
			}
			compressedTarget := bufio.NewReader(dstFile)
			dstImagePath := strings.TrimSuffix(dstPath, ".zst")

			return dstImagePath, extractZst(ctx, compressedTarget, dstImagePath)
		}

	default:
		return image, fmt.Errorf("unexpected tar header type %d", hdr.Typeflag)
	}

	return image, nil
}

func extractZst(ctx context.Context, reader io.Reader, dstPath string) error {
	dstDir, dstName := filepath.Split(dstPath)

	var tmpPath string
	if tmpf, err := os.CreateTemp(dstDir, fmt.Sprintf("%s-*", dstName)); err != nil {
		return err
	} else {
		tmpPath = tmpf.Name()
		tmpf.Close()
		// NB: remove temp file in case something goes wrong
		defer os.Remove(tmpPath)
	}

	// NB: we need to force with -f, because the destination file exists (we created it)
	cmd := exec.CommandContext(ctx, "zstd", "-d", "-", "-o", tmpPath, "-f")
	cmd.Stdin = reader

	if _, err := cmd.Output(); err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			os.Stderr.Write(e.Stderr)
		}
		return fmt.Errorf("failed during zst decompression to %s: %w", dstPath, err)
	}

	return os.Rename(tmpPath, dstPath)
}
