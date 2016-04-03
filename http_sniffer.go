package main

import (
	"bufio"
	"bytes"
	"github.com/julsemaan/garin/util"
	"net/http"
)

func ParseHTTP(packet *util.Packet) *Destination {
	Logger().Debug(packet.Hosts, packet.Ports)
	buf := bytes.NewBuffer(packet.Payload)
	read := bufio.NewReader(buf)
	request, err := http.ReadRequest(read)
	// Errors are normal, especially when we read responses
	if err != nil {
		Logger().Debug(err)
	} else if request.Host != "" {
		return NewDestination(request.Host, packet.Hosts.Src().String())
	}
	return nil
}
