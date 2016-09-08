package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/julsemaan/garin/base"
	"github.com/op/go-logging"
	"github.com/revel/cmd/harness"
	"github.com/revel/revel"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

var cfgFile = flag.String("c", "/etc/garin.conf", "Configuration to use for execution")
var cfg = BuildConfig(*cfgFile)

var unencryptedPorts = make(map[string]bool)
var encryptedPorts = make(map[string]bool)

var parsingConcurrency = flag.Int("parsing-concurrency", cfg.General.Parsing_concurrency, "Amount of concurrent threads that will parse the incoming traffic")
var parsingConcurrencyChan = make(chan int, *parsingConcurrency)

var recordingThreads = flag.Int("recording-threads", cfg.General.Recording_threads, "Amount of concurrent threads that will work the recording queue (used to persist parsed data)")
var dontRecordDestinations = flag.Bool("dont-record-destinations", cfg.General.Dont_record_destinations, "Don't record the destinations in the DB backend")

var wg sync.WaitGroup

var recordingQueue = NewRecordingQueue()

var unencryptedPortsArg = flag.String("unencrypted-ports", cfg.Capture.Unencrypted_ports, "The ports on which to parse unencrypted HTTP traffic")
var encryptedPortsArg = flag.String("encrypted-ports", cfg.Capture.Encrypted_ports, "The ports on which to parse encrypted HTTPS traffic")

var iface = flag.String("i", cfg.Capture.Interface, "Interface to get packets from")
var pcapFile = flag.String("o", "", "PCAP file to read from (ignores -i)")
var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet")
var bufferedPerConnection = flag.Int("connection-max-buffer", cfg.Capture.Buffered_per_connection, `
Max packets to buffer for a single connection before skipping over a gap in data
and continuing to stream the connection after the buffer.  If zero or less, this
is infinite.`)
var bufferedTotal = flag.Int("total-max-buffer", cfg.Capture.Total_max_buffer, `
Max packets to buffer total before skipping over gaps in connections and
continuing to stream connection data.  If zero or less, this is infinite`)
var flushAfter = flag.String("flush-after", cfg.Capture.Flush_after, `
Connections which have buffered packets (they've gotten packets out of order and
are waiting for old packets to fill the gaps) are flushed after they're this old
(their oldest gap is skipped).  Any string parsed by time.ParseDuration is
acceptable here`)
var debounceDestinations = flag.String("debounce-destinations", cfg.Database.Debounce_destinations, `
Debounce the destinations recording by the duration specified in this parameter.
If set to 20s, then the same destination will only be saved once every 20 seconds.
This can be used to reduce the logging of all activity related to a domain (like fetching HTML + assets)`)

var running = true
var stopChan = make(chan int, 1)

func Logger() *logging.Logger {
	return base.LoggerWithLevel(cfg.General.Log_level)
}

func main() {
	defer util.Run()()
	var err error

	var allPorts []string
	ports := regexp.MustCompile(",").Split(*unencryptedPortsArg, -1)
	allPorts = append(allPorts, ports...)
	for _, port := range ports {
		unencryptedPorts[port] = true
	}
	ports = regexp.MustCompile(",").Split(*encryptedPortsArg, -1)
	allPorts = append(allPorts, ports...)
	for _, port := range ports {
		encryptedPorts[port] = true
	}

	filter := "tcp port " + strings.Join(allPorts, " or ")

	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		base.Die("invalid flush duration: ", *flushAfter)
	}

	debounceThreshold, err := time.ParseDuration(*debounceDestinations)
	if err != nil {
		base.Die("invalid debounce destinations duration: ", *debounceDestinations)
	} else {
		recordingQueue.SetDebounceThreshold(debounceThreshold)
	}

	//go func() {
	//	Logger().Info(http.ListenAndServe("localhost:6060", nil))
	//}()

	if !*dontRecordDestinations {
		for i := 1; i <= *recordingThreads; i++ {
			Logger().Info("Spawning recording thread", i)
			wg.Add(1)
			go func() {
				db := base.NewGarinDB(cfg.Database.Type, cfg.Database.Args)
				defer db.Close()
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

	//go runWeb()

	go func() {
		tick := time.Tick(flushDuration)
		for _ = range tick {
			debug.FreeOSMemory()
		}
	}()

	// Set up pcap packet capture
	var handle *pcap.Handle
	if *pcapFile != "" {
		Logger().Infof("starting capture from file %q", *pcapFile)
		handle, err = pcap.OpenOffline(*pcapFile)
	} else {
		Logger().Infof("starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(cfg.Capture.Snaplen), true, flushDuration/2)
	}
	if err != nil {
		base.Die("error opening pcap handle: ", err.Error())
	}

	Logger().Info("Using filter", filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		base.Die("error setting BPF filter: ", err)
	}

	// Set up assembly
	streamFactory := &sniffStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = *bufferedPerConnection
	assembler.MaxBufferedPagesTotal = *bufferedTotal

	Logger().Info("reading in packets")

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
		Logger().Infof("processed %d bytes in %v", byteCount, time.Since(start))
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
		// Check to see if we should flush the streams we have
		// that haven't seen any new data in a while.  Note we set a
		// timeout on our PCAP handle, so this should happen even if we
		// never see packet data.
		if time.Now().After(nextFlush) {
			stats, _ := handle.Stats()
			Logger().Infof("flushing all streams that haven't seen packets in the last %q, pcap stats: %+v", *flushAfter, stats)
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

		// We wait for either a stop sign or for a packet - whichever comes first
		// If we detect we need to stop, we signal it to the group and we stop
		select {
		case <-packetIn:
		case <-stopChan:
			wg.Done()
			return
		}

		if err != nil {
			if err.Error() == "EOF" {
				// Read all packets in the case of a pcap file
				Logger().Info("Read all packets")
				wg.Done()
				return
			} else {
				Logger().Errorf("error getting packet: %v", err)
				continue
			}
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			Logger().Errorf("error decoding packet: %v", err)
			continue
		}
		if *logAllPackets {
			Logger().Debugf("decoded the following layers: %v", decoded)
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
					Logger().Debug("could not find IPv4 or IPv6 layer, inoring")
				}
				continue loop
			}
		}
		Logger().Debug("could not find TCP layer")
	}
	wg.Done()

}

func runStatsServer() {

}

func runWeb() {
	// Determine the run mode.
	mode := "dev"
	port := 9090

	// Find and parse app.conf
	revel.Init(mode, "github.com/julsemaan/garin/web", "")
	revel.LoadMimeConfig()

	revel.INFO.Printf("Running %s (%s) in %s mode\n", revel.AppName, revel.ImportPath, mode)
	revel.TRACE.Println("Base path:", revel.BasePath)

	// If the app is run in "watched" mode, use the harness to run it.
	if revel.Config.BoolDefault("watch", true) && revel.Config.BoolDefault("watch.code", true) {
		revel.TRACE.Println("Running in watched mode.")
		revel.HttpPort = port
		harness.NewHarness().Run() // Never returns.
	}

	// Else, just build and run the app.
	revel.TRACE.Println("Running in live build mode.")
	app, err := harness.Build()
	if err != nil {
		base.Die("Failed to build app:", err)
	}
	app.Port = port
	app.Cmd().Run()
}
