package https_sniffer

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	//"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"log"
	//	"os"
)

type Packet struct {
	Hosts   gopacket.Flow
	Ports   gopacket.Flow
	Payload []byte
}

type TLSPacket struct {
	tlsVersion    uint16
	contentType   uint8
	length        uint16
	handshakeType uint8

	serverName string
}

type TLSClientHello struct {
	sessionId  string
	serverName string
}

type TLSServerHello struct {
	sessionId  string
	serverName string
}

type TLSServerCertExchange struct {
	serverName   string
	certificates []*x509.Certificate
}

func readBigEndian16(buf *bytes.Buffer) uint16 {
	var x uint16
	binary.Read(buf, binary.BigEndian, &x)
	return x
}

func readBigEndian24(buf *bytes.Buffer) uint32 {
	threeBytesEndian := buf.Next(3)
	fourBytesEndian := append([]byte{0}, threeBytesEndian...)
	tmpBuf := bytes.NewBuffer(fourBytesEndian)

	var x uint32
	binary.Read(tmpBuf, binary.BigEndian, &x)
	return x
}

func readUint8(buf *bytes.Buffer) uint8 {
	return uint8(buf.Next(1)[0])
}

func readTLSHeader(buf *bytes.Buffer) {
	// 3 bytes length, 2 bytes TLS version 4 bytes timestamp, 28 random bytes
	buf.Next(3 + 2 + 4 + 28)
}

func (self *TLSServerHello) Parse(tlsPacket *TLSPacket, buf *bytes.Buffer) {
	readTLSHeader(buf)

	// Read session ID if there
	sessionIdLength := readUint8(buf)
	self.sessionId = hex.EncodeToString(buf.Next(int(sessionIdLength)))

	// In SSL, we have the certs directly in the server hello
	// so we read them here
	if !tlsPacket.isTLS() {
		//skip cipher suite
		buf.Next(2)
		compressionMethod := readUint8(buf)
		if compressionMethod != 0 {
			log.Println("Can't decrypt certs because they are compressed and we don't know how to uncompress them...")
		} else {
			handshakeType := readUint8(buf)
			if handshakeType == 11 {
				// we skip the length of the whole
				buf.Next(3)
				certificates := readCertificates(buf)
				self.serverName = certificates[0].Subject.CommonName
			} else {
				log.Println("Unknown SSL handshake type")
			}
		}
	}

}

func readCertificates(buf *bytes.Buffer) []*x509.Certificate {
	certificatesLength := readBigEndian24(buf)

	log.Println("Certs length", certificatesLength)

	var certificates []*x509.Certificate

	i := 0
	for i < int(certificatesLength) {
		certificateLength := readBigEndian24(buf)
		certificate_bytes := buf.Next(int(certificateLength))
		tmpCertificates, err := x509.ParseCertificates(certificate_bytes)
		if err != nil {
			log.Println("Can't decode certificate")
		}
		certificate := tmpCertificates[0]

		certificates = append(certificates, certificate)

		i += int(certificatesLength + 1)
	}

	return certificates
}

func (self *TLSClientHello) Parse(tlsPacket *TLSPacket, buf *bytes.Buffer) {
	readTLSHeader(buf)

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

func (self *TLSServerCertExchange) Parse(tlsPacket *TLSPacket, buf *bytes.Buffer) {
	// we skip the length of the whole
	buf.Next(3)

	self.certificates = readCertificates(buf)

	self.serverName = self.certificates[0].Subject.CommonName
}

func (self *TLSPacket) isTLS() bool {
	return (self.tlsVersion >= 0x301)
}

func (self *TLSPacket) Parse(buf *bytes.Buffer) {
	self.contentType = readUint8(buf)
	self.tlsVersion = readBigEndian16(buf)
	self.length = readBigEndian16(buf)
	self.handshakeType = readUint8(buf)
	// if its a Client Hello and we're not coming from a Server Hello
	if self.handshakeType == 1 {
		log.Println("Found client hello")
		client_hello := TLSClientHello{}
		client_hello.Parse(self, buf)
		//spew.Dump(hello)
		self.serverName = client_hello.serverName
	} else if self.handshakeType == 2 {
		log.Println("Found server hello")
		// We read the whole server hello but not doing anything with it yet
		server_hello_bytes := buf.Next(int(self.length) - 1)
		server_hello_buf := bytes.NewBuffer(server_hello_bytes)

		server_hello := TLSServerHello{}
		server_hello.Parse(self, server_hello_buf)

		// a session ID indicates the initial handshake is completed, thus won't contain our certs
		// Most likely a cipher change
		// But, if we are in SSL, we have the certs with the hello, so the server name will be there
		if server_hello.sessionId == "" {
			cert_exchange := &TLSPacket{}
			cert_exchange.Parse(buf)
		} else if !self.isTLS() {
			log.Println("Dealing with non-TLS exchange")
			self.serverName = server_hello.serverName
		}

	} else if self.handshakeType == 11 {
		log.Println("Found cert exchange")
		cert_exchange := &TLSServerCertExchange{}
		cert_exchange.Parse(self, buf)
		self.serverName = cert_exchange.serverName
	}

	if self.serverName != "" {
		log.Println("Found the following server name : ", self.serverName)
	}
}

func (self *Packet) Parse() {
	if self.Ports.Src().String() == "443" || self.Ports.Dst().String() == "443" {
		//		log.Println("Packet source", self.Hosts.Src().String(), ":", self.Ports.Src().String())
		log.Println(self.Hosts, self.Ports)
		buf := bytes.NewBuffer(self.Payload)
		tlsPacket := &TLSPacket{}
		tlsPacket.Parse(buf)
		//		spew.Dump(self)
		//		os.Exit(0)
	}
}
