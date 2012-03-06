package convergence

import (
	"encoding/gob"
	"code.google.com/p/leveldb-go/leveldb/memdb"
	"code.google.com/p/leveldb-go/leveldb/db"
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
	options *db.Options
	writeOptions *db.WriteOptions
	readOptions *db.ReadOptions
}

func NewStore() Store{
	options := &db.Options{}
	writeOptions := &db.WriteOptions{Sync:false}
	readOptions := &db.ReadOptions{}
	return leveldbStore{MemDB: memdb.New(nil),options:options,writeOptions:writeOptions,readOptions:readOptions}
}

func (l leveldbStore) Get(key []byte) (value interface{}, err error){
	var val []byte
	val, err = l.MemDB.Get(key,l.readOptions)
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
	err = l.MemDB.Set(key,buf.Bytes(),l.writeOptions)
	return err
	
}

func (l leveldbStore)     Delete(key []byte) error{
	return l.MemDB.Delete(key, l.writeOptions)
}

