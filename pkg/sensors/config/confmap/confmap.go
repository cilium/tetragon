// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package confmap

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
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
			logger.GetLogger().WithField("bpf-map", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
			return err
		}
	}

	defer m.Close()

	k := &TetragonConfKey{Key: 0}
	v := &TetragonConfValue{
		// TODO complete
		Mode:        0,
		CgrpFsMagic: 0,
		NSPID:       uint32(nspid),
	}

	err = m.Update(k, v)
	if err != nil {
		logger.GetLogger().WithField("bpf-map", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
		return err
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"bpf-map": configMap.Name,
		"NSPID":   nspid,
	}).Info("Updated TetragonConf map successfully")

	return nil
}
