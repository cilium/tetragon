// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package confmap

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/sirupsen/logrus"
)

type TetragonConfKey struct {
	Key uint32
}

type TetragonConfValue struct {
	Mode        uint32 // Deployment mode
	LogLevel    uint32 // Tetragon log level
	PID         uint32 // Tetragon PID for debugging purpose
	NSPID       uint32 // Tetragon PID in namespace for debugging purpose
	TgCgrpLevel uint32 // Tetragon cgroup level
	Pad         uint32
	TgCgrpId    uint64 // Tetragon cgroup ID
	CgrpFsMagic uint64 // Cgroupv1 or cgroupv2
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

func UpdateTetragonConfMap(mapDir string, nspid int) error {
	configMap := base.GetTetragonConfMap()
	mapPath := filepath.Join(mapDir, configMap.Name)

	m, err := bpf.OpenMap(mapPath)
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(mapPath)
		if err != nil {
			time.Sleep(1 * time.Second)
		}
		if i > 4 {
			log.WithField("bpf-map", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
			return err
		}
	}

	defer m.Close()

	cgroupFsMagic, err := cgroups.GetBpfCgroupFS()
	if err != nil {
		log.WithField("bpf-map", configMap.Name).WithError(err).Warnf("Cgroupfs detection failed, falling back to Cgroupv1")
		// Let's fallback to Cgroupv1 so we can use raw cgroup bpf code and avoid
		// cgroupv2 helpers
		cgroupFsMagic = unix.CGROUP_SUPER_MAGIC
	}

	k := &TetragonConfKey{Key: 0}
	v := &TetragonConfValue{
		// TODO complete
		Mode:        0,
		LogLevel:    uint32(logger.GetLogLevel()),
		NSPID:       uint32(nspid),
		CgrpFsMagic: cgroupFsMagic,
	}

	err = m.Update(k, v)
	if err != nil {
		log.WithField("bpf-map", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
		return err
	}

	log.WithFields(logrus.Fields{
		"bpf-map":       configMap.Name,
		"LogLevel":      logrus.Level(v.LogLevel).String(),
		"NSPID":         nspid,
		"CgroupFSMagic": cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
	}).Info("Updated TetragonConf map successfully")

	return nil
}
