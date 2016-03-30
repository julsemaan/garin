package destination

import (
	"time"
)

type Destination struct {
	SourceIp   string
	ServerName string
	Timestamp  time.Time
}

func New(serverName string, sourceIp string) *Destination {
	destination := &Destination{ServerName: serverName, SourceIp: sourceIp, Timestamp: time.Now()}
	return destination
}
