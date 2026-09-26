// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/policyfilter"
)

// Each distinct binary costs a full uprobe sensor, while replicas of one
// image share it.
const maxBinariesPerPolicy = 64

type containerRef struct {
	podID       policyfilter.PodID
	containerID string
}

func (ref containerRef) String() string {
	return ref.podID.String() + "/" + ref.containerID
}

type loadedSensor interface {
	Load(bpfDir string) error
	Destroy(unpin bool) error
}

type sensorBuilder func(name string, binary *os.File) (loadedSensor, error)

type rootResolver func(context.Context, policyfilter.ContainerChange) (*containerRoot, error)

type loadedBinary struct {
	sensor     loadedSensor
	containers int
}

// containerUprobeReconciler attaches the policy's uprobe to the binary behind
// each container the policyfilter reports, one sensor per distinct binary.
// The sensors are owned here rather than by the sensor manager, so teardown
// never re-enters it.
type containerUprobeReconciler struct {
	procFS      string
	target      string
	bpfDir      string
	build       sensorBuilder
	resolveRoot rootResolver

	// cancel aborts a root lookup in flight when stopping.
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	// Only a container's latest change matters, and containers are
	// independent, so pending holds one change per container.
	pending map[containerRef]policyfilter.ContainerChange
	stopped bool
	wake    chan struct{}
	done    chan struct{}

	// Owned by the run goroutine.
	attached map[containerRef]fileKey
	loaded   map[fileKey]*loadedBinary
	capHit   bool
}

func newContainerUprobeReconciler(procFS, target, bpfDir string, build sensorBuilder, resolveRoot rootResolver) *containerUprobeReconciler {
	ctx, cancel := context.WithCancel(context.Background())
	r := &containerUprobeReconciler{
		ctx:         ctx,
		cancel:      cancel,
		procFS:      procFS,
		target:      target,
		bpfDir:      bpfDir,
		build:       build,
		resolveRoot: resolveRoot,
		pending:     map[containerRef]policyfilter.ContainerChange{},
		wake:        make(chan struct{}, 1),
		done:        make(chan struct{}),
		attached:    map[containerRef]fileKey{},
		loaded:      map[fileKey]*loadedBinary{},
	}
	go r.run()
	return r
}

// push queues a change without blocking, as the policyfilter calls it under
// its lock.
func (r *containerUprobeReconciler) push(c policyfilter.ContainerChange) {
	r.mu.Lock()
	if !r.stopped {
		r.pending[containerRef{c.PodID, c.ContainerID}] = c
	}
	r.mu.Unlock()
	r.signal()
}

func (r *containerUprobeReconciler) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// stop detaches everything and returns once the sensors are gone.
func (r *containerUprobeReconciler) stop() {
	r.mu.Lock()
	r.stopped = true
	clear(r.pending)
	r.mu.Unlock()
	r.cancel()
	r.signal()
	<-r.done
}

func (r *containerUprobeReconciler) run() {
	defer close(r.done)
	defer r.detachAll()
	for range r.wake {
		for {
			c, ok, stopped := r.next()
			if stopped {
				return
			}
			if !ok {
				break
			}
			r.apply(c)
		}
	}
}

// next takes a pending change, in no particular order.
func (r *containerUprobeReconciler) next() (policyfilter.ContainerChange, bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return policyfilter.ContainerChange{}, false, true
	}
	for ref, c := range r.pending {
		delete(r.pending, ref)
		return c, true, false
	}
	return policyfilter.ContainerChange{}, false, false
}

func (r *containerUprobeReconciler) apply(c policyfilter.ContainerChange) {
	ref := containerRef{c.PodID, c.ContainerID}
	if c.Removed {
		r.detach(ref)
		return
	}
	if _, ok := r.attached[ref]; ok {
		return
	}
	if err := r.attach(ref, c); err != nil {
		logger.GetLogger().Warn("uprobe resolvePathInContainer: skipping container",
			logfields.Error, err, "container", ref, "path", r.target)
	}
}

// Sidecars legitimately lack the target and replicas may run another build,
// so those containers are skipped quietly.
func (r *containerUprobeReconciler) attach(ref containerRef, c policyfilter.ContainerChange) error {
	root, err := r.resolveRoot(r.ctx, c)
	if err != nil {
		return err
	}
	defer root.release()

	binary, st, err := resolveBinaryUnderRoot(root.dir, r.target)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, errNotRegularFile) || errors.Is(err, errTargetTooLarge) {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: path missing or unusable in container",
			logfields.Error, err, "container", ref, "path", r.target)
		return nil
	}
	if err != nil {
		return err
	}
	// Held open until the load completes so the inode cannot be swapped.
	defer binary.Close()

	key := backingFileID(r.procFS, root, r.target, &st)
	if lb, ok := r.loaded[key]; ok {
		lb.containers++
		r.attached[ref] = key
		return nil
	}
	if len(r.loaded) >= maxBinariesPerPolicy {
		if !r.capHit {
			r.capHit = true
			logger.GetLogger().Warn("uprobe resolvePathInContainer: per-policy binary cap reached; "+
				"containers with other binaries will not be traced", "cap", maxBinariesPerPolicy)
		}
		return nil
	}

	sensor, err := r.load(key, binary)
	if _, ok := errors.AsType[*DigestMismatchError](err); ok {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: container binary digest mismatch",
			logfields.Error, err, "container", ref)
		return nil
	}
	if err != nil {
		return err
	}
	r.loaded[key] = &loadedBinary{sensor: sensor, containers: 1}
	r.attached[ref] = key
	return nil
}

func (r *containerUprobeReconciler) load(key fileKey, binary *os.File) (loadedSensor, error) {
	// Unique within the policy, whose directory holds the sensor's pins.
	name := fmt.Sprintf("generic_uprobe_ric_%d_%d", key.dev, key.ino)
	sensor, err := r.build(name, binary)
	if err != nil {
		return nil, fmt.Errorf("building uprobe sensor %s: %w", name, err)
	}
	if err := sensor.Load(r.bpfDir); err != nil {
		if derr := sensor.Destroy(true); derr != nil {
			err = errors.Join(err, derr)
		}
		return nil, fmt.Errorf("loading uprobe sensor %s: %w", name, err)
	}
	return sensor, nil
}

func (r *containerUprobeReconciler) detach(ref containerRef) {
	key, ok := r.attached[ref]
	if !ok {
		return
	}
	delete(r.attached, ref)
	lb := r.loaded[key]
	if lb.containers--; lb.containers == 0 {
		delete(r.loaded, key)
		r.destroy(lb.sensor)
	}
}

func (r *containerUprobeReconciler) detachAll() {
	for _, lb := range r.loaded {
		r.destroy(lb.sensor)
	}
	clear(r.loaded)
	clear(r.attached)
}

func (r *containerUprobeReconciler) destroy(sensor loadedSensor) {
	if err := sensor.Destroy(true); err != nil {
		logger.GetLogger().Warn("uprobe resolvePathInContainer: failed to destroy sensor",
			logfields.Error, err)
	}
}
