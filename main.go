package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/julsemaan/WebSniffer/destination"
	"github.com/julsemaan/WebSniffer/http_sniffer"
	"github.com/julsemaan/WebSniffer/https_sniffer"
	"github.com/julsemaan/WebSniffer/log"
	//"net/http"
	_ "net/http/pprof"
	"runtime/debug"
	"time"
)

var concurrency = flag.Int("concurrency", 1, "Amount of concurrent threads that will be run")
var concurrencyChan = make(chan int, *concurrency)
var iface = flag.String("i", "eth0", "Interface to get packets from")
var pcapFile = flag.String("o", "", "PCAP file to read from (ignores -i)")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet")
var bufferedPerConnection = flag.Int("connection_max_buffer", 0, `
Max packets to buffer for a single connection before skipping over a gap in data
and continuing to stream the connection after the buffer.  If zero or less, this
is infinite.`)
var bufferedTotal = flag.Int("total_max_buffer", 0, `
Max packets to buffer total before skipping over gaps in connections and
continuing to stream connection data.  If zero or less, this is infinite`)
var flushAfter = flag.String("flush_after", "2m", `
Connections which have buffered packets (they've gotten packets out of order and
are waiting for old packets to fill the gaps) are flushed after they're this old
(their oldest gap is skipped).  Any string parsed by time.ParseDuration is
acceptable here`)
var packetCount = flag.Int("c", -1, `
Quit after processing this many packets, flushing all currently buffered
connections.  If negative, this is infinite`)

// simpleStreamFactory implements tcpassembly.StreamFactory
type sniffStreamFactory struct{}

// sniffStream will handle the actual decoding of sniff requests.
type sniffStream struct {
	net, transport                         gopacket.Flow
	bytesLen, packets, outOfOrder, skipped int64
	start, end                             time.Time
	sawStart, sawEnd                       bool
	bytes                                  []byte
}

// New creates a new stream.  It's called whenever the assembler sees a stream
// it isn't currently following.
func (factory *sniffStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	//	log.Printf("new stream %v:%v started", net, transport)
	s := &sniffStream{
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	s.end = s.start
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return s
}

// Reassembled is called whenever new packet data is available for reading.
// Reassembly objects contain stream data IN ORDER.
func (s *sniffStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if reassembly.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = reassembly.Seen
		}
		s.bytesLen += int64(len(reassembly.Bytes))
		s.packets += 1
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.bytes = append(s.bytes, reassembly.Bytes...)
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End
	}
}

// ReassemblyComplete is called when the TCP assembler believes a stream has
// finished.
func (s *sniffStream) ReassemblyComplete() {
	//diffSecs := float64(s.end.Sub(s.start)) / float64(time.Second)
	//	log.Printf("Reassembly of stream %v:%v complete - start:%v end:%v bytes:%v packets:%v ooo:%v bps:%v pps:%v skipped:%v",
	//s.net, s.transport, s.start, s.end, s.bytesLen, s.packets, s.outOfOrder,
	//float64(s.bytesLen)/diffSecs, float64(s.packets)/diffSecs, s.skipped)

	concurrencyChan <- 1
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Logger().Debug("Error decoding packet. This may be normal.", r)
			}
			<-concurrencyChan
		}()

		var destination *destination.Destination
		http_packet := http_sniffer.Packet{Hosts: s.net, Ports: s.transport, Payload: s.bytes}
		destination = http_packet.Parse()

		https_packet := https_sniffer.Packet{Hosts: s.net, Ports: s.transport, Payload: s.bytes}
		destination = https_packet.Parse()

		log.Logger().Info("Found the following server name : ", destination.ServerName)
		<-concurrencyChan
	}()
}

func main() {
	defer util.Run()()
	var err error

	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Die("invalid flush duration: ", *flushAfter)
	}

	//go func() {
	//	log.Logger().Info(http.ListenAndServe("localhost:6060", nil))
	//}()

	go func() {
		tick := time.Tick(flushDuration)
		for _ = range tick {
			debug.FreeOSMemory()
		}
	}()

	log.Logger().Infof("starting capture on interface %q", *iface)
	// Set up pcap packet capture
	var handle *pcap.Handle
	if *pcapFile != "" {
		handle, err = pcap.OpenOffline(*pcapFile)
	} else {
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, flushDuration/2)
	}
	if err != nil {
		log.Die("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Die("error setting BPF filter: ", err)
	}

	// Set up assembly
	streamFactory := &sniffStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = *bufferedPerConnection
	assembler.MaxBufferedPagesTotal = *bufferedTotal

	log.Logger().Info("reading in packets")

	// We use a DecodingLayerParser here instead of a simpler PacketSource.
	// This approach should be measurably faster, but is also more rigid.
	// PacketSource will handle any known type of packet safely and easily,
	// but DecodingLayerParser will only handle those packet types we
	// specifically pass in.  This trade-off can be quite useful, though, in
	// high-throughput situations.
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ip6extensions layers.IPv6ExtensionSkipper
	var tcp layers.TCP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	nextFlush := time.Now().Add(flushDuration / 2)

	var byteCount int64
	start := time.Now()

loop:
	for ; *packetCount != 0; *packetCount-- {
		// Check to see if we should flush the streams we have
		// that haven't seen any new data in a while.  Note we set a
		// timeout on our PCAP handle, so this should happen even if we
		// never see packet data.
		if time.Now().After(nextFlush) {
			stats, _ := handle.Stats()
			log.Logger().Infof("flushing all streams that haven't seen packets in the last %q, pcap stats: %+v", *flushAfter, stats)
			assembler.FlushOlderThan(time.Now().Add(flushDuration))
			nextFlush = time.Now().Add(flushDuration / 2)
		}

		// To speed things up, we're also using the ZeroCopy method for
		// reading packet data.  This method is faster than the normal
		// ReadPacketData, but the returned bytes in 'data' are
		// invalidated by any subsequent ZeroCopyReadPacketData call.
		// Note that tcpassembly is entirely compatible with this packet
		// reading method.  This is another trade-off which might be
		// appropriate for high-throughput sniffing:  it avoids a packet
		// copy, but its cost is much more careful handling of the
		// resulting byte slice.
		data, ci, err := handle.ZeroCopyReadPacketData()

		if err != nil {
			if err.Error() == "EOF" {
				// Read all packets in the case of a pcap file
				log.Logger().Info("Read all packets")
				return
			} else {
				log.Logger().Errorf("error getting packet: %v", err)
				continue
			}
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Logger().Errorf("error decoding packet: %v", err)
			continue
		}
		if *logAllPackets {
			log.Logger().Debugf("decoded the following layers: %v", decoded)
		}
		byteCount += int64(len(data))
		// Find either the IPv4 or IPv6 address to use as our network
		// layer.
		foundNetLayer := false
		var netFlow gopacket.Flow
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				netFlow = ip4.NetworkFlow()
				foundNetLayer = true
			case layers.LayerTypeIPv6:
				netFlow = ip6.NetworkFlow()
				foundNetLayer = true
			case layers.LayerTypeTCP:
				if foundNetLayer {
					assembler.AssembleWithTimestamp(netFlow, &tcp, ci.Timestamp)
				} else {
					log.Logger().Debug("could not find IPv4 or IPv6 layer, inoring")
				}
				continue loop
			}
		}
		log.Logger().Debug("could not find TCP layer")
	}
	assembler.FlushAll()
	log.Logger().Info("processed %d bytes in %v", byteCount, time.Since(start))
}
