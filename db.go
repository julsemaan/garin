package main

import (
	"sync"
)

var creationMutex = &sync.Mutex{}

var dbExists = false

type GarinDB interface {
	Open()
	Close()
	checkIfExists() bool
	createIfNotExists()
	RecordDestination(*Destination)
}

type AbstractGarinDB struct {
	dbType string
	dbArgs string
}

func (self *AbstractGarinDB) checkIfExists() bool {
	if dbExists {
		return true
	} else {
		return false
	}
}

func (self *AbstractGarinDB) createIfNotExists() {
	panic("unimplemented")
}

func NewGarinDB(dbType string, dbArgs string) GarinDB {
	if dbType != "mongodb" {
		db := &SQLGarinDB{}
		db.dbType = dbType
		db.dbArgs = dbArgs
		db.Open()
		db.createIfNotExists()
		return db
	} else {
		return nil
	}
}
