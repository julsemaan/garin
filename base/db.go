package base

import (
	"sync"
)

var creationMutex = &sync.Mutex{}

var dbExists = false

const DESTINATIONS_TABLE_NAME = "destinations"

type GarinDB interface {
	Setup(string, string)
	Open()
	Close()
	RecordDestination(*Destination)
}

type AbstractGarinDB struct {
	dbType string
	dbArgs string
}

func (self *AbstractGarinDB) Setup(dbType string, dbArgs string) {
	self.dbType = dbType
	self.dbArgs = dbArgs
}

func (self *AbstractGarinDB) Open() {
	panic("unimplemented")
}

func (self *AbstractGarinDB) Close() {
	panic("unimplemented")
}

func (self *AbstractGarinDB) RecordDestination(destination *Destination) {
	panic("unimplemented")
}

func NewGarinDB(dbType string, dbArgs string) GarinDB {
	var db GarinDB
	switch dbType {
	case "mongodb":
		db = &MongoGarinDB{}
	default:
		db = &SQLGarinDB{}
	}

	db.Setup(dbType, dbArgs)
	db.Open()
	return db
}
