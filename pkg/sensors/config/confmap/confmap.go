// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package confmap

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type TetragonConfKey struct {
	Key uint32
}

type TetragonConfValue struct {
	Mode        uint32
	LogLevel    uint32
	PID         uint32
	NSPID       uint32
	TgCgrpLevel uint32
	Pad         uint32
	TGCgrpId    uint64
	CgrpFsMagic uint64
}

var (
	log = logger.GetLogger()
)

func (k *TetragonConfKey) String() string             { return fmt.Sprintf("key=%d", k.Key) }
func (k *TetragonConfKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *TetragonConfKey) DeepCopyMapKey() bpf.MapKey { return &TetragonConfKey{k.Key} }

func (k *TetragonConfKey) NewValue() bpf.MapValue { return &TetragonConfValue{} }

func (v *TetragonConfValue) String() string {
	return fmt.Sprintf("value=%d %s", 0, "")
}
func (v *TetragonConfValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *TetragonConfValue) DeepCopyMapValue() bpf.MapValue {
	return &TetragonConfValue{}
}

func UpdateTetragonConfMap(mapDir string, pid int) error {
	configMap := base.GetTetragonConfMap()

	mapPath := filepath.Join(mapDir, configMap.Name)
	log.WithField("map", configMap.Name).Debugf("updating TetragonConfMap %q", mapPath)

	cgroupFsMagic, err := cgroups.GetBpfCgroupFS()
	if err != nil {
		log.WithError(err).Warnf("Cgroupfs detection failed, falling back to Cgroupv1")
		// Let's fallback to Cgroupv1 so we can use raw cgroup bpf code and avoid
		// Cgroupv2 bpf helpers
		cgroupFsMagic = unix.CGROUP_SUPER_MAGIC
	}

	m, err := bpf.OpenMap(mapPath)
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(mapPath))
		if err != nil {
			time.Sleep(1 * time.Second)
		}
		if i > 4 {
			log.WithField("map", configMap.Name).WithError(err).Warn("Failed to open TetragonConfMap")
			return err
		}
	}

	defer m.Close()

	k := &TetragonConfKey{Key: 0}
	v := &TetragonConfValue{
		// TODO complete
		Mode:        0,
		LogLevel:    uint32(logger.GetLogLevel()),
		NSPID:       uint32(pid),
		CgrpFsMagic: cgroupFsMagic,
	}

	err = m.Update(k, v)
	if err != nil {
		log.WithField("map", configMap.Name).WithError(err).Warn("Failed to update TetragonConfMap")
		return err
	}

	log.WithField("map", configMap.Name).WithFields(logrus.Fields{
		"LogLevel":      logrus.Level(v.LogLevel).String(),
		"NSPID":         v.NSPID,
		"CgroupFSMagic": cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
	}).Infof("updated TetragonConfMap %q successfully", mapPath)

	return nil
}
