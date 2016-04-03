package main

import (
	"github.com/julsemaan/WebSniffer/log"
	"gopkg.in/mgo.v2"
)

type MongoGarinDB struct {
	AbstractGarinDB
	Session *mgo.Session
}

func (self *MongoGarinDB) Open() {
	session, err := mgo.Dial(self.dbArgs)

	if err != nil {
		log.Die(err)
	}

	self.Session = session
	self.Session.SetMode(mgo.Monotonic, true)
}

func (self *MongoGarinDB) Close() {
	self.Session.Close()
}

func (self *MongoGarinDB) RecordDestination(destination *Destination) {
	c := self.Session.DB("").C(DESTINATIONS_TABLE_NAME)
	err := c.Insert(destination)
	if err != nil {
		panic(err)
	}
}
