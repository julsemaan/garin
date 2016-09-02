package base

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type SQLGarinDB struct {
	AbstractGarinDB
	Handle *sqlx.DB
}

func (self *SQLGarinDB) Open() {
	db, err := sqlx.Open(self.dbType, self.dbArgs)
	if err != nil {
		Die(err)
	}

	self.Handle = db
	self.createIfNotExists()
}

func (self *SQLGarinDB) Close() {
	self.Handle.Close()
}

func (self *SQLGarinDB) checkIfExists() bool {
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

func (self *SQLGarinDB) createIfNotExists() {
	creationMutex.Lock()
	self._createIfNotExists()
	creationMutex.Unlock()
}

func (self *SQLGarinDB) _createIfNotExists() {
	if self.checkIfExists() {
		return
	}
	schema := `
		create table destinations (source_ip VARCHAR(15), destination_ip VARCHAR(15), server_name VARCHAR(100), protocol VARCHAR(10),timestamp DATE);
	`
	// exec the schema or fail; multi-statement Exec behavior varies between
	// database drivers;  pq will exec them all, sqlite3 won't, ymmv
	self.Handle.MustExec(schema)
}

func (self *SQLGarinDB) RecordDestination(destination *Destination) {
	_, err := self.Handle.NamedExec("INSERT INTO "+DESTINATIONS_TABLE_NAME+" (source_ip, destination_ip, server_name, protocol, timestamp) VALUES(:source_ip, :destination_ip, :server_name, :protocol, :timestamp)", destination)
	if err != nil {
		panic(err)
	}
}
