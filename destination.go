package main

import (
	"github.com/julsemaan/WebSniffer/log"
	"time"
)

type Destination struct {
	SourceIp   string    `db:"source_ip"`
	ServerName string    `db:"server_name"`
	Timestamp  time.Time `db:"timestamp"`
}

func NewDestination(serverName string, sourceIp string) *Destination {
	destination := &Destination{ServerName: serverName, SourceIp: sourceIp, Timestamp: time.Now()}
	return destination
}

func (self *Destination) Save(db *WebSnifferDB) {
	log.Logger().Info("Saving destination")
	_, err := db.Handle.NamedExec("INSERT INTO destinations (source_ip, server_name, timestamp) VALUES(:source_ip, :server_name, :timestamp)", self)
	if err != nil {
		panic(err)
	}
	//db.Handle.MustExec(`INSERT INTO destinations (source_ip, server_name, timestamp) VALUES('allo', 'allo', 0)`)
	log.Logger().Info("Destination saved")
}
