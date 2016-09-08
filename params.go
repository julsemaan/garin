package main

import (
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"regexp"
)

type Params struct {
	UnencryptedPorts       map[string]bool
	EncryptedPorts         map[string]bool
	AllPorts               []string
	ParsingConcurrency     int
	RecordingThreads       int
	DontRecordDestinations bool
	Iface                  string
	PcapFile               string
	LogAllPackets          bool
	BufferedPerConnection  int
	BufferedTotal          int
	FlushAfter             string
	DebounceDestinations   string
}

func NewParams(cfg Config) *Params {
	params := &Params{}

	params.UnencryptedPorts = make(map[string]bool)
	params.EncryptedPorts = make(map[string]bool)

	params.ParsingConcurrency = *flag.Int("-parsing-concurrency", cfg.General.Parsing_concurrency, "Amount of concurrent threads that will parse the incoming traffic")

	params.RecordingThreads = *flag.Int("-recording-threads", cfg.General.Recording_threads, "Amount of concurrent threads that will work the recording queue (used to persist parsed data)")
	params.DontRecordDestinations = *flag.Bool("-dont-record-destinations", cfg.General.Dont_record_destinations, "Don't record the destinations in the DB backend")

	var unencryptedPortsArg = *flag.String("-unencrypted-ports", cfg.Capture.Unencrypted_ports, "The ports on which to parse unencrypted HTTP traffic")
	var encryptedPortsArg = *flag.String("-encrypted-ports", cfg.Capture.Encrypted_ports, "The ports on which to parse encrypted HTTPS traffic")

	params.UnencryptedPorts = make(map[string]bool)
	params.EncryptedPorts = make(map[string]bool)

	var allPorts []string
	ports := regexp.MustCompile(",").Split(unencryptedPortsArg, -1)
	allPorts = append(allPorts, ports...)
	for _, port := range ports {
		params.UnencryptedPorts[port] = true
	}
	ports = regexp.MustCompile(",").Split(encryptedPortsArg, -1)
	allPorts = append(allPorts, ports...)
	for _, port := range ports {
		params.EncryptedPorts[port] = true
	}

	params.AllPorts = allPorts

	params.Iface = *flag.String("i", cfg.Capture.Interface, "Interface to get packets from")
	params.PcapFile = *flag.String("-offline-pcap", "", "PCAP file to read from (ignores -i)")
	params.LogAllPackets = *flag.Bool("-log-all-packets", false, "Log whenever we see a packet")
	params.BufferedPerConnection = *flag.Int("-connection-max-buffer", cfg.Capture.Buffered_per_connection, `Max packets to buffer for a single connection before skipping over a gap in data
	and continuing to stream the connection after the buffer.  If zero or less, this
	is infinite.`)
	params.BufferedTotal = *flag.Int("-total-max-buffer", cfg.Capture.Total_max_buffer, `Max packets to buffer total before skipping over gaps in connections and
	continuing to stream connection data.  If zero or less, this is infinite`)
	params.FlushAfter = *flag.String("-flush-after", cfg.Capture.Flush_after, `Connections which have buffered packets (they've gotten packets out of order and
	are waiting for old packets to fill the gaps) are flushed after they're this old
	(their oldest gap is skipped).  Any string parsed by time.ParseDuration is
	acceptable here`)

	params.DebounceDestinations = *flag.String("-debounce-destinations", cfg.Database.Debounce_destinations, `Debounce the destinations recording by the duration specified in this parameter.
	If set to 20s, then the same destination will only be saved once every 20 seconds.
	This can be used to reduce the logging of all activity related to a domain (like fetching HTML + assets)`)

	fmt.Println("Starting using parameters : ", spew.Sdump(params))
	return params
}
