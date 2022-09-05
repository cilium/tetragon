package observer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"
)

func init() {
	RegisterEventHandlerAtInit(ops.MSG_OP_DATA, HandleData)
}

var (
	dataMap *lru.Cache[dataapi.DataEventId, []byte]
)

func InitDataCache(size int) error {
	var err error

	dataMap, err = lru.New[dataapi.DataEventId, []byte](size)
	return err
}

func add(r *bytes.Reader, m *dataapi.MsgData) error {
	size := m.Common.Size - uint32(unsafe.Sizeof(*m))
	msgData := make([]byte, size)

	err := binary.Read(r, binary.LittleEndian, &msgData)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read data msg payload")
		return err
	}

	data, ok := dataMap.Get(m.Id)
	if !ok {
		dataMap.Add(m.Id, msgData)
	} else {
		data = append(data, msgData...)
		dataMap.Add(m.Id, data)
	}

	logger.GetLogger().Debugf("Data message received id %v, size %v, total %v", m.Id, size, len(data))
	return nil
}

func DataGet(id dataapi.DataEventId) ([]byte, error) {
	data, ok := dataMap.Get(id)
	if !ok {
		return nil, fmt.Errorf("failed to find data for id: %v", id)
	}

	dataMap.Remove(id)
	logger.GetLogger().Debugf("Data message used id %v, data len %v", id, len(data))
	return data, nil
}

func HandleData(r *bytes.Reader) ([]Event, error) {
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
