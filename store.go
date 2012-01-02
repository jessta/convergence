package convergence

import (
	"encoding/gob"
	"code.google.com/p/leveldb-go/leveldb/memdb"
	"bytes"
)

func init() {
	gob.Register(SeenCert{})
}

type Store interface {
    Close() error
    Delete(key []byte) error
    Get(key []byte) (value interface{}, err error)
    Set(key []byte, value interface{}) error	
}

type leveldbStore struct {
	*memdb.MemDB
}

func NewStore() Store{
	return leveldbStore{memdb.New(nil)}
}

func (l leveldbStore) Get(key []byte) (value interface{}, err error){
	var val []byte
	val, err = l.MemDB.Get(key)
	g := gob.NewDecoder(bytes.NewBuffer(val))
	err = g.Decode(&value)
	if err != nil {
		return nil,err
	}
	return value,err
}

func (l leveldbStore) Set(key []byte, value interface{}) error {
	var buf bytes.Buffer
	g := gob.NewEncoder(&buf)
	err := g.Encode(value)
	if err != nil {
		return err
	}
	err = l.MemDB.Set(key,buf.Bytes())
	return err
	
}
