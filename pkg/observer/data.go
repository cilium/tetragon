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

func DataAdd(id dataapi.DataEventId, msgData []byte) error {
	size := len(msgData)
	data, ok := dataMap.Get(id)
	if !ok {
		dataMap.Add(id, msgData)
		DataEventMetricInc(DataEventAdded)
	} else {
		data = append(data, msgData...)
		dataMap.Add(id, data)
		DataEventMetricInc(DataEventAppended)
	}

	logger.GetLogger().WithFields(nil).Tracef("Data message received id %v, size %v, total %v", id, size, len(data))
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
	data, ok := dataMap.Get(desc.Id)
	if !ok {
		DataEventMetricInc(DataEventNotMatched)
		return nil, fmt.Errorf("failed to find data for id: %v", desc.Id)
	}

	dataMap.Remove(desc.Id)

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
		return nil, fmt.Errorf("Failed to read data msg")
	}

	err = add(r, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to add data msg")
	}

	// we don't send the event further
	return nil, nil
}

func DataPurge() {
	dataMap.Purge()
}
