package base

import (
	"time"
)

type Destination struct {
	SourceIp   string    `db:"source_ip"`
	ServerName string    `db:"server_name"`
	Protocol   string    `db:"protocol"`
	Timestamp  time.Time `db:"timestamp"`
}

func NewDestination(serverName string, sourceIp string) *Destination {
	destination := &Destination{ServerName: serverName, SourceIp: sourceIp, Timestamp: time.Now()}
	return destination
}

func (self *Destination) Save(db GarinDB) {
	Logger().Info("Saving destination")
	db.RecordDestination(self)
	//db.Handle.MustExec(`INSERT INTO destinations (source_ip, server_name, timestamp) VALUES('allo', 'allo', 0)`)
	Logger().Info("Destination saved")
}
