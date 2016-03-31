package main

import (
	"github.com/jmoiron/sqlx"
	"github.com/julsemaan/WebSniffer/log"
	_ "github.com/mattn/go-sqlite3"
)

var dbExists = false

const defaultDbType = "sqlite3"
const defaultDbArgs = "/home/julien/gopath/src/github.com/julsemaan/WebSniffer/db.sqlite3"

type WebSnifferDB struct {
	dbType string
	dbArgs string
	Handle *sqlx.DB
}

func (self *WebSnifferDB) open() {
	db, err := sqlx.Open(self.dbType, self.dbArgs)
	if err != nil {
		log.Die(err)
	}

	self.Handle = db
}

func (self *WebSnifferDB) checkIfExists() bool {
	if dbExists {
		return true
	}
	_, err := self.Handle.Exec("select * from destinations limit 1")
	if err != nil {
		return false
	} else {
		dbExists = true
		return true
	}
}

func (self *WebSnifferDB) createIfNotExists() {
	if self.checkIfExists() {
		return
	}
	schema := `
		create table destinations (source_ip VARCHAR(15), server_name VARCHAR(100), timestamp DATE);
		delete from destinations;
	`
	// exec the schema or fail; multi-statement Exec behavior varies between
	// database drivers;  pq will exec them all, sqlite3 won't, ymmv
	self.Handle.MustExec(schema)
}

func NewWebSnifferDB(dbType string, dbArgs string) *WebSnifferDB {
	db := &WebSnifferDB{dbType: dbType, dbArgs: dbArgs}
	db.open()
	db.createIfNotExists()
	return db
}

func GetDB() *WebSnifferDB {
	return NewWebSnifferDB(defaultDbType, defaultDbArgs)
}
