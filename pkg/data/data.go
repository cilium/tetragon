package data

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
)

func init() {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_DATA, handleData)
}

var (
	dataMap map[dataapi.DataEventId][]byte = make(map[dataapi.DataEventId][]byte)
)

func add(r *bytes.Reader, m *dataapi.MsgData) error {
	size := m.Common.Size - uint32(unsafe.Sizeof(*m))
	msgData := make([]byte, size)

	err := binary.Read(r, binary.LittleEndian, &msgData)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read data msg payload")
		return err
	}

	data := dataMap[m.Id]
	if data == nil {
		dataMap[m.Id] = msgData
	} else {
		data = append(data, msgData...)
		dataMap[m.Id] = data
	}

	logger.GetLogger().Debugf("Data message received id %v, size %v, total %v", m.Id, size, len(data))
	return nil
}

func Get(id dataapi.DataEventId) ([]byte, error) {
	data := dataMap[id]
	if data == nil {
		return nil, fmt.Errorf("failed to find data for id: %v", id)
	}

	delete(dataMap, id)
	logger.GetLogger().Debugf("Data message used id %v, data len %v", id, len(data))
	return data, nil
}

func handleData(r *bytes.Reader) ([]observer.Event, error) {
	m := dataapi.MsgData{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to read data msg")
	}

	err = add(r, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to add data msg")
	}

	// we don't send the event further
	return nil, nil
}
