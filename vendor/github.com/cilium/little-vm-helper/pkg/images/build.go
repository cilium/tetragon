// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package images

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// BuildConf configures how a set of images are build
type BuildConf struct {
	Log *logrus.Logger

	// if DryRun set, no actual images will be build. Instead, empty files will be created
	DryRun bool
	// if ForceRebuild is set, images will be build even if they exist already
	ForceRebuild bool
	// if MergeSteps is set, image build steps will be merged when possible (better performance at the cost making operations more complicated)
	MergeSteps bool
}

// BuildImageResult describes the result of building a single image
type BuildImageResult struct {
	// Error is not nil, if building the image failed.
	Error error

	// CachedImageUsed is set to true if a cached image was found and no
	// actual build happened.
	CachedImageUsed bool

	// CachedImageDeleted is set to an non empty string if the image file
	// was deleted. The string describes the reason.
	CachedImageDeleted string
}

// BuilderResult encodes the result of building a set of images
type BuilderResult struct {
	// Error is not nil if an error happened outside image builds
	Error error
	// ImageResults results of building images
	ImageResults map[string]BuildImageResult
}

// BuildImage builds an image, with all of its dependencies
func (f *ImageForest) BuildImage(bldConf *BuildConf, image string) (*BuilderResult, error) {
	deps, err := f.Dependencies(image)
	if err != nil {
		return nil, err
	}

	log := bldConf.Log
	st := newBuildState(f, bldConf)
	images := append(deps, image)
	for i := range images {
		imgRes := st.buildImage(images[i])
		xlog := log.WithFields(logrus.Fields{
			"image":    image[i],
			"all-deps": images,
			"result":   fmt.Sprintf("%+v", imgRes),
		})
		if imgRes.Error == nil {
			xlog.Info("image built succesfully")
		} else {
			xlog.Warn("image build failed")
			break
		}
	}

	return &st.bldResult, nil
}

// BuildAllImages will build all images in the forest. It will start from the
// roots, and work its way down.
func (f *ImageForest) BuildAllImages(bldConf *BuildConf) *BuilderResult {
	return f.BuildImages(bldConf, f.RootImages())
}

// BuildImages will build the images specified in the queue from the forest. It
// will start from the roots, and work its way down.
func (f *ImageForest) BuildImages(bldConf *BuildConf, queue []string) *BuilderResult {
	log := bldConf.Log
	st := newBuildState(f, bldConf)
	log.WithFields(logrus.Fields{
		"queue": strings.Join(queue, ","),
	}).Info("starting to build images")
	for {
		var image string
		if len(queue) == 0 {
			break
		}
		image, queue = queue[0], queue[1:]
		imgRes := st.buildImage(image)
		if imgRes.Error == nil {
			children := f.children[image]
			queue = append(queue, children...)
		}

		xlog := log.WithFields(logrus.Fields{
			"image":  image,
			"queue":  strings.Join(queue, ","),
			"result": fmt.Sprintf("%+v", imgRes),
		})
		if imgRes.Error == nil {
			xlog.Info("image built succesfully")
		} else {
			xlog.Warn("image build failed")
		}
	}

	return &st.bldResult
}

// Err() returns a summary error or nil if no errors were encountered
func (r *BuilderResult) Err() error {
	var imgErr strings.Builder
	imgErr.WriteString("images errors:")
	errCount := 0
	for image, res := range r.ImageResults {
		if res.Error != nil {
			if errCount > 0 {
				imgErr.WriteString("; ")
			}
			imgErr.WriteString(fmt.Sprintf("%s: %v", image, res.Error))
			errCount++
		}
	}

	if errCount == 0 {
		return r.Error
	}

	if r.Error == nil {
		return errors.New(imgErr.String())
	} else {
		return fmt.Errorf("builder error:%w %s", r.Error, imgErr.String())
	}
}

func (b *buildState) doBuildImage(image string) BuildImageResult {

	imgRes := b.skipRebuild(image)
	if imgRes.Error != nil || imgRes.CachedImageUsed {
		return imgRes
	}

	buildImage := func(image string) error {
		return b.f.doBuildImage(context.Background(), b.bldConf.Log, image, b.bldConf.MergeSteps)
	}
	if b.bldConf.DryRun {
		buildImage = b.f.doBuildImageDryRun
	}
	imgRes.Error = buildImage(image)
	return imgRes
}
