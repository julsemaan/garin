package main

import (
	"sync"
)

var creationMutex = &sync.Mutex{}

var dbExists = false

type WebSnifferDBInt interface {
	Open()
	Close()
	checkIfExists() bool
	createIfNotExists()
	RecordDestination(*Destination)
}

type WebSnifferDB struct {
	dbType string
	dbArgs string
}

func (self *WebSnifferDB) checkIfExists() bool {
	if dbExists {
		return true
	} else {
		return false
	}
}

func (self *WebSnifferDB) createIfNotExists() {
	panic("unimplemented")
}

func NewWebSnifferDB(dbType string, dbArgs string) WebSnifferDBInt {
	if dbType != "mongodb" {
		db := &SQLWebSnifferDB{}
		db.dbType = dbType
		db.dbArgs = dbArgs
		db.Open()
		db.createIfNotExists()
		return db
	} else {
		return nil
	}
}
