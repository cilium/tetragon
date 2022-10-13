package buildid

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"

	lru "github.com/hashicorp/golang-lru"
)

type data struct {
	buildid []byte
}

var (
	cache *lru.Cache
)

func InitCache() error {
	var err error

	cache, err = lru.New(4096)
	return err
}

func Set(filename string, buildid []byte) error {
	if cache == nil {
		return fmt.Errorf("buildid cache not initialized")
	}

	_, ok := cache.Get(filename)
	if !ok {
		data := &data{
			buildid: buildid,
		}
		cache.Add(filename, data)
		BIDMetricInc(BIDTypeSetOk)
	} else {
		BIDMetricInc(BIDTypeSetDup)
	}
	return nil
}

func Get(filename string) ([]byte, error) {
	if cache == nil {
		return []byte{}, fmt.Errorf("buildid cache not initialized")
	}

	value, ok := cache.Get(filename)
	if ok {
		data, ok := value.(*data)
		if !ok {
			return []byte{}, fmt.Errorf("Data message internal error (add)")
		}
		BIDMetricInc(BIDTypeGetOk)
		return data.buildid, nil
	}
	BIDMetricInc(BIDTypeGetFail)
	return []byte{}, fmt.Errorf("buildid not found")
}

type note struct {
	Namesz uint32
	Descsz uint32
	Typ    uint32
}

func align(v, a uint32) uint32 {
	return ((v + 1) / a) * a
}

func parseNote(dat []byte) ([]byte, bool) {
	var note note

	dr := bytes.NewReader(dat)

	for {
		if err := binary.Read(dr, binary.LittleEndian, &note); err != nil {
			return []byte{}, false
		}

		name := make([]byte, align(note.Namesz, 4))
		if err := binary.Read(dr, binary.LittleEndian, name); err != nil {
			return []byte{}, false
		}

		desc := make([]byte, align(note.Descsz, 4))
		if err := binary.Read(dr, binary.LittleEndian, desc); err != nil {
			return []byte{}, false
		}

		if note.Typ == 3 &&
			note.Namesz == 4 &&
			bytes.Equal(name, []byte{'G', 'N', 'U', 0}) &&
			note.Descsz > 0 && note.Descsz <= 20 {
			return desc, true
		}
	}
}

func ParseBuildId(filename string) ([]byte, error) {
	f, err := elf.Open(filename)
	if err != nil {
		return []byte{}, err
	}
	defer f.Close()

	for _, ph := range f.Progs {
		if ph.Type != elf.PT_NOTE {
			continue
		}
		dat := make([]byte, ph.Filesz)
		_, err := io.ReadFull(ph.Open(), dat)
		if err != nil {
			continue
		}
		bid, ok := parseNote(dat)
		if ok {
			return bid, nil
		}
	}
	return []byte{}, nil
}

func Store(filename string) error {
	id, err := ParseBuildId(filename)
	if err != nil {
		return err
	}
	return Set(filename, id)
}
