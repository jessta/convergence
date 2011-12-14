package convergence

import (
	"encoding/gob"
	"gocask.googlecode.com/hg"
)

func init() {
	gob.Register(SeenCert{})
}

type DiskStore struct {
	*gocask.Gocask
}

func (s DiskStore) Get(key string) (interface{}, error) {
	/*val, err := s.Get(key)
	if err != nil {
		return nil, err
	}
	gob.Decode(val)*/

	return nil, nil
}

func (s DiskStore) Put(key string, val interface{}) error {
	//gob.NewEncoder
	return nil
}

func (s DiskStore) Close() error {
	return nil
}
