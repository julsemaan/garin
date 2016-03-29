package http_sniffer

import (
	"bufio"
	"bytes"
	"github.com/google/gopacket"
	"github.com/julsemaan/WebSniffer/log"
	"net/http"
)

type Packet struct {
	Hosts   gopacket.Flow
	Ports   gopacket.Flow
	Payload []byte
}

func (self *Packet) Parse() {
	if self.Ports.Src().String() == "80" || self.Ports.Dst().String() == "80" {
		log.Logger().Debug(self.Hosts, self.Ports)
		buf := bytes.NewBuffer(self.Payload)
		read := bufio.NewReader(buf)
		request, err := http.ReadRequest(read)
		// Errors are normal, especially when we read responses
		if err != nil {
			log.Logger().Debug(err)
		} else {
			log.Logger().Info("Found the following server name : ", request.Host)
		}
	}
}
