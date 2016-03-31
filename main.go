package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/julsemaan/WebSniffer/log"
	WebSnifferUtil "github.com/julsemaan/WebSniffer/util"
	"os/signal"
	"regexp"
	//"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

var unencryptedPorts = make(map[string]bool)
var encryptedPorts = make(map[string]bool)

var parsingConcurrency = flag.Int("parsing-concurrency", 1, "Amount of concurrent threads that will parse the incoming traffic")
var parsingConcurrencyChan = make(chan int, *parsingConcurrency)

var recordingThreads = flag.Int("recording-threads", 1, "Amount of concurrent threads that will work the recording queue (used to persist parsed data)")
var dontRecordDestinations = flag.Bool("dont-record-destinations", false, "Don't record the destinations in the DB backend")

var wg sync.WaitGroup

var recordingQueue = NewRecordingQueue()

var unencryptedPortsArg = flag.String("unencrypted-ports", "80", "The ports on which to parse unencrypted HTTP traffic")
var encryptedPortsArg = flag.String("encrypted-ports", "443", "The ports on which to parse encrypted HTTPS traffic")
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

var running = true
var stopChan = make(chan int, 1)

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

	go func() {
		wg.Add(1)
		parsingConcurrencyChan <- 1

		defer func() {
			if r := recover(); r != nil {
				err, ok := r.(error)
				if ok && err.Error() == "runtime error: index out of range" {
					log.Logger().Debug("Error decoding packet due to its unknown format. This is likely normal.", err.Error())
				} else {
					log.Logger().Error("Error decoding packet.", r)
				}
			}
			<-parsingConcurrencyChan
			wg.Done()
		}()

		var destination *Destination
		if unencryptedPorts[s.transport.Src().String()] || unencryptedPorts[s.transport.Dst().String()] {
			http_packet := &WebSnifferUtil.Packet{Hosts: s.net, Ports: s.transport, Payload: s.bytes}
			destination = ParseHTTP(http_packet)
			if destination != nil {
				log.Logger().Info("Found the following server name (HTTP) : ", destination.ServerName)
				recordingQueue.push(destination)
			}
		}

		if encryptedPorts[s.transport.Src().String()] || encryptedPorts[s.transport.Dst().String()] {
			https_packet := &WebSnifferUtil.Packet{Hosts: s.net, Ports: s.transport, Payload: s.bytes}
			destination = ParseHTTPS(https_packet)
			if destination != nil {
				log.Logger().Info("Found the following server name (HTTPS) : ", destination.ServerName)
				recordingQueue.push(destination)
			}
		}

		<-parsingConcurrencyChan
		wg.Done()
	}()
}

func main() {
	defer util.Run()()
	var err error

	ports := regexp.MustCompile(",").Split(*unencryptedPortsArg, -1)
	for _, port := range ports {
		unencryptedPorts[port] = true
	}
	ports = regexp.MustCompile(",").Split(*encryptedPortsArg, -1)
	for _, port := range ports {
		encryptedPorts[port] = true
	}

	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Die("invalid flush duration: ", *flushAfter)
	}

	//go func() {
	//	log.Logger().Info(http.ListenAndServe("localhost:6060", nil))
	//}()

	if !*dontRecordDestinations {
		for i := 1; i <= *recordingThreads; i++ {
			log.Logger().Info("Spawning recording thread", i)
			wg.Add(1)
			go func() {
				db := GetDB()
				defer db.Handle.Close()
				for running || !recordingQueue.empty() {
					if !recordingQueue.work(db) {
						// When the queue hasn't provided something, we sleep to save some CPU time
						time.Sleep(time.Millisecond * 10)
					}
				}
				wg.Done()
			}()
		}
	} else {
		recordingQueue.dummy = true
	}

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

	stop := func() {
		running = false
		stopChan <- 1
		wg.Wait()
		assembler.FlushAll()
		log.Logger().Infof("processed %d bytes in %v", byteCount, time.Since(start))
		os.Exit(0)
	}

	defer stop()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, os.Kill)
	go func() {
		for _ = range c {
			stop()
		}
	}()

	wg.Add(1)
loop:
	for running {
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

			var data []byte
			var ci gopacket.CaptureInfo
			var err error
			packetIn := make(chan int, 1)
			go func() {
				// To speed things up, we're also using the ZeroCopy method for
				// reading packet data.  This method is faster than the normal
				// ReadPacketData, but the returned bytes in 'data' are
				// invalidated by any subsequent ZeroCopyReadPacketData call.
				// Note that tcpassembly is entirely compatible with this packet
				// reading method.  This is another trade-off which might be
				// appropriate for high-throughput sniffing:  it avoids a packet
				// copy, but its cost is much more careful handling of the
				// resulting byte slice.
				data, ci, err = handle.ZeroCopyReadPacketData()
				packetIn <- 1
			}()

			done := false
			for !done {
				select {
				case <-packetIn:
					done = true
				case <-stopChan:
					done = true
					wg.Done()
					return
				}
			}

			if err != nil {
				if err.Error() == "EOF" {
					// Read all packets in the case of a pcap file
					log.Logger().Info("Read all packets")
					wg.Done()
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
	}
	wg.Done()

}
