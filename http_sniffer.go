package WebSniffer

import (
	"bufio"
	"bytes"
	"github.com/julsemaan/WebSniffer/log"
	"github.com/julsemaan/WebSniffer/util"
	"net/http"
)

func ParseHTTP(packet *util.Packet) *Destination {
	if packet.Ports.Src().String() == "80" || packet.Ports.Dst().String() == "80" {
		log.Logger().Debug(packet.Hosts, packet.Ports)
		buf := bytes.NewBuffer(packet.Payload)
		read := bufio.NewReader(buf)
		request, err := http.ReadRequest(read)
		// Errors are normal, especially when we read responses
		if err != nil {
			log.Logger().Debug(err)
		} else if request.Host != "" {
			return NewDestination(request.Host, packet.Hosts.Src().String())
		}
	}
	return nil
}
