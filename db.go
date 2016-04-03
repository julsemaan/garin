package main

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/julsemaan/WebSniffer/log"
	_ "github.com/mattn/go-sqlite3"
	"sync"
)

var creationMutex = &sync.Mutex{}

var dbExists = false

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

func (self *WebSnifferDB) Close() {
	self.Handle.Close()
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
	creationMutex.Lock()
	if self.checkIfExists() {
		return
	}
	schema := `
		create table destinations (source_ip VARCHAR(15), server_name VARCHAR(100), timestamp DATE);
	`
	// exec the schema or fail; multi-statement Exec behavior varies between
	// database drivers;  pq will exec them all, sqlite3 won't, ymmv
	self.Handle.MustExec(schema)
	creationMutex.Unlock()
}

func NewWebSnifferDB(dbType string, dbArgs string) *WebSnifferDB {
	db := &WebSnifferDB{dbType: dbType, dbArgs: dbArgs}
	db.open()
	db.createIfNotExists()
	return db
}
