package https_sniffer

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"log"
	"os"
)

type TLSPacket struct {
	Hosts   gopacket.Flow
	Ports   gopacket.Flow
	Payload []byte

	contentType   uint8
	tlsVersion    uint16
	length        uint16
	handshakeType uint8

	serverName string
}

type TLSClientHello struct {
	tlsVersion uint16
	sessionId  string
	serverName string
}

func readBigEndian16(buf *bytes.Buffer) uint16 {
	var x uint16
	binary.Read(buf, binary.BigEndian, &x)
	return x
}

func readUint8(buf *bytes.Buffer) uint8 {
	return uint8(buf.Next(1)[0])
}

func (self *TLSClientHello) Parse(tlsPacket *TLSPacket, buf *bytes.Buffer) {
	//we skip the length
	buf.Next(3)
	self.tlsVersion = readBigEndian16(buf)
	// 4 bytes timestamp, 28 random bytes
	buf.Next(4 + 28)

	// Read session ID if there
	sessionIdLength := readUint8(buf)
	self.sessionId = hex.EncodeToString(buf.Next(int(sessionIdLength)))

	// Read ciphers suites
	cipherSuitesLength := readBigEndian16(buf)
	buf.Next(int(cipherSuitesLength))

	// Read compression methods
	compressionMethodsLength := readUint8(buf)
	buf.Next(int(compressionMethodsLength))

	extensionsLength := int(readBigEndian16(buf))
	if extensionsLength > 0 {
		i := 0
		for i < extensionsLength {
			extensionType := readBigEndian16(buf)
			extensionLength := readBigEndian16(buf)

			// if its the server name, then we analyse. Otherwise, we skip the extension
			if extensionType == 0 {
				// list length (2 bytes), server name type 1 byte, length 2 bytes
				buf.Next(3)
				serverNameLength := readBigEndian16(buf)
				self.serverName = string(buf.Next(int(serverNameLength)))
				break
			} else {
				buf.Next(int(extensionLength))
			}

			// length + the extension type + extension length
			i += int(extensionLength + 4)
		}
	}
}

func (self *TLSPacket) Parse() {
	if self.Ports.Src().String() == "443" || self.Ports.Dst().String() == "443" {
		buf := bytes.NewBuffer(self.Payload)
		self.contentType = readUint8(buf)
		self.tlsVersion = readBigEndian16(buf)
		self.length = readBigEndian16(buf)
		self.handshakeType = readUint8(buf)
		log.Println("Packet source", self.Hosts.Src().String(), ":", self.Ports.Src().String())
		if self.handshakeType == 1 {
			hello := TLSClientHello{}
			hello.Parse(self, buf)
			spew.Dump(hello)
			if hello.serverName != "" {
				self.serverName = hello.serverName
			}
		}

		if self.serverName != "" {
			log.Println("Found the following server name : ", self.serverName)
		}
		spew.Dump(self)
		os.Exit(0)
	}
}
