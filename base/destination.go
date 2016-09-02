package base

import (
	"time"
)

type Destination struct {
	SourceIp      string    `db:"source_ip"`
	DestinationIp string    `db:"destination_ip"`
	ServerName    string    `db:"server_name"`
	Protocol      string    `db:"protocol"`
	Timestamp     time.Time `db:"timestamp"`
}

func NewDestination(serverName string, sourceIp string, destIp string) *Destination {
	destination := &Destination{ServerName: serverName, SourceIp: sourceIp, DestinationIp: destIp, Timestamp: time.Now()}
	return destination
}

func (self *Destination) Save(db GarinDB) {
	Logger().Debug("Saving destination")
	db.RecordDestination(self)
	//db.Handle.MustExec(`INSERT INTO destinations (source_ip, server_name, timestamp) VALUES('allo', 'allo', 0)`)
	Logger().Debug("Destination saved")
}
