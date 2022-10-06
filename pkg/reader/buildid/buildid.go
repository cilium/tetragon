package buildid

import (
	"fmt"

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
		return data.buildid, nil
	}
	return []byte{}, fmt.Errorf("buildid not found")
}
