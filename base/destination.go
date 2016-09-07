package base

import (
	"crypto/md5"
	"fmt"
	"time"
)

type Destination struct {
	SourceIp      string    `db:"source_ip"`
	DestinationIp string    `db:"destination_ip"`
	ServerName    string    `db:"server_name"`
	Protocol      string    `db:"protocol"`
	Timestamp     time.Time `db:"timestamp"`
}

func (self *Destination) Hash() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(self.SourceIp+self.DestinationIp+self.ServerName+self.Protocol)))
}

func NewDestination(serverName string, sourceIp string, destIp string) *Destination {
	destination := &Destination{ServerName: serverName, SourceIp: sourceIp, DestinationIp: destIp}
	return destination
}

func (self *Destination) Save(db GarinDB) {
	Logger().Debug("Saving destination")
	db.RecordDestination(self)
	Logger().Debug("Destination saved")
}
