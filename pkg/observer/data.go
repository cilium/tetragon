// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/logger"
)

func init() {
	RegisterEventHandlerAtInit(ops.MSG_OP_DATA, HandleData)
}

var (
	dataCache *cache
)

func InitDataCache(size int) error {
	var err error
	dataCache, err = newCache(size)
	return err
}

func DataAdd(id dataapi.DataEventId, msgData []byte) error {
	size := len(msgData)
	data, err := dataCache.get(id)
	if err != nil {
		dataCache.add(id, msgData)
		DataEventMetricInc(DataEventAdded)
	} else {
		data = append(data, msgData...)
		dataCache.add(id, data)
		DataEventMetricInc(DataEventAppended)
		logger.GetLogger().WithFields(nil).Tracef("Data message received id %v, size %v, total %v", id, size, len(data))
	}

	return nil
}

func add(r *bytes.Reader, m *dataapi.MsgData) error {
	size := m.Common.Size - uint32(unsafe.Sizeof(*m))
	msgData := make([]byte, size)

	err := binary.Read(r, binary.LittleEndian, &msgData)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read data msg payload")
		return err
	}

	return DataAdd(m.Id, msgData)
}

func DataGet(desc dataapi.DataEventDesc) ([]byte, error) {
	data, err := dataCache.get(desc.Id)
	if err != nil {
		DataEventMetricInc(DataEventNotMatched)
		return nil, err
	}

	dataCache.remove(desc)

	// make sure we did not loose anything on the way through ring buffer
	if len(data) != int(desc.Size-desc.Leftover) {
		DataEventMetricInc(DataEventBad)
		DataEventMetricSizeBad(desc.Size)
		return nil, fmt.Errorf("failed to get correct data for id: %v", desc.Id)
	}

	DataEventMetricSizeOk(desc.Size)

	logger.GetLogger().WithFields(nil).Tracef("Data message used id %v, data len %v", desc.Id, len(data))
	DataEventMetricInc(DataEventMatched)
	return data, nil
}

func HandleData(r *bytes.Reader) ([]Event, error) {
	DataEventMetricInc(DataEventReceived)

	m := dataapi.MsgData{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, errors.New("failed to read data msg")
	}

	err = add(r, &m)
	if err != nil {
		return nil, errors.New("failed to add data msg")
	}

	// we don't send the event further
	return nil, nil
}

func DataPurge() {
	dataCache.cache.Purge()
}
