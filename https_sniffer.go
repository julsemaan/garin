package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"github.com/julsemaan/garin/base"
	"github.com/julsemaan/garin/util"
)

type TLSPacket struct {
	tlsVersion    uint16
	contentType   uint8
	length        uint16
	handshakeType uint8

	serverName string
}

type TLSExchange struct {
	serverName string
}

type TLSClientHello struct {
	TLSExchange
	sessionId string
}

type TLSServerHello struct {
	TLSExchange
	sessionId string
}

type TLSServerCertExchange struct {
	TLSExchange
	certificates []*x509.Certificate
}

func readTLSHeader(buf *bytes.Buffer) {
	// 3 bytes length, 2 bytes TLS version 4 bytes timestamp, 28 random bytes
	buf.Next(3 + 2 + 4 + 28)
}

func (self *TLSServerHello) Parse(tlsPacket *TLSPacket, buf *bytes.Buffer) {
	readTLSHeader(buf)

	// Read session ID if there
	sessionIdLength := util.ReadUint8(buf)
	self.sessionId = hex.EncodeToString(buf.Next(int(sessionIdLength)))

	// In SSL, we have the certs directly in the server hello
	// so we read them here
	if !tlsPacket.isTLS() {
		//skip cipher suite
		buf.Next(2)
		compressionMethod := util.ReadUint8(buf)
		if compressionMethod != 0 {
			Logger().Error("Can't decrypt certs because they are compressed and we don't know how to uncompress them...")
		} else {
			handshakeType := util.ReadUint8(buf)
			if handshakeType == 11 {
				// we skip the length of the whole
				buf.Next(3)
				certificates := self.readCertificates(buf)
				self.serverName = certificates[0].Subject.CommonName
			} else {
				Logger().Error("Unknown SSL handshake type")
			}
		}
	}

}

func (self *TLSExchange) readCertificates(buf *bytes.Buffer) []*x509.Certificate {
	certificatesLength := util.ReadBigEndian24(buf)

	var certificates []*x509.Certificate

	i := 0
	for i < int(certificatesLength) {
		certificateLength := util.ReadBigEndian24(buf)
		certificate_bytes := buf.Next(int(certificateLength))
		tmpCertificates, err := x509.ParseCertificates(certificate_bytes)
		if err != nil {
			Logger().Error("Can't decode certificate")
		}
		certificate := tmpCertificates[0]

		certificates = append(certificates, certificate)

		i += int(certificatesLength + 1)
	}

	return certificates
}

func (self *TLSClientHello) Parse(tlsPacket *TLSPacket, buf *bytes.Buffer) {
	// Non-TLS packets don't contain the server name extension
	if !tlsPacket.isTLS() {
		return
	}

	readTLSHeader(buf)

	// Read session ID if there
	sessionIdLength := util.ReadUint8(buf)
	self.sessionId = hex.EncodeToString(buf.Next(int(sessionIdLength)))

	// Read ciphers suites
	cipherSuitesLength := util.ReadBigEndian16(buf)
	buf.Next(int(cipherSuitesLength))

	// Read compression methods
	compressionMethodsLength := util.ReadUint8(buf)
	buf.Next(int(compressionMethodsLength))

	extensionsLength := int(util.ReadBigEndian16(buf))
	if extensionsLength > 0 {
		i := 0
		for i < extensionsLength {
			extensionType := util.ReadBigEndian16(buf)
			extensionLength := util.ReadBigEndian16(buf)

			// if its the server name, then we analyse. Otherwise, we skip the extension
			if extensionType == 0 {
				// list length (2 bytes), server name type 1 byte, length 2 bytes
				buf.Next(3)
				serverNameLength := util.ReadBigEndian16(buf)
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

	self.certificates = self.readCertificates(buf)

	self.serverName = self.certificates[0].Subject.CommonName
}

func (self *TLSPacket) isTLS() bool {
	return (self.tlsVersion >= 0x301)
}

func (self *TLSPacket) Parse(buf *bytes.Buffer) {
	self.contentType = util.ReadUint8(buf)
	self.tlsVersion = util.ReadBigEndian16(buf)
	self.length = util.ReadBigEndian16(buf)
	self.handshakeType = util.ReadUint8(buf)
	// if its a Client Hello and we're not coming from a Server Hello
	if self.handshakeType == 1 {
		Logger().Debug("Found client hello")
		client_hello := TLSClientHello{}
		client_hello.Parse(self, buf)
		//spew.Dump(hello)
		self.serverName = client_hello.serverName
	} else if self.handshakeType == 2 {
		Logger().Debug("Found server hello")
		// We read the whole server hello but not doing anything with it yet
		server_hello_bytes := buf.Next(int(self.length) - 1)
		server_hello_buf := bytes.NewBuffer(server_hello_bytes)

		server_hello := TLSServerHello{}
		server_hello.Parse(self, server_hello_buf)

		// a session ID indicates the initial handshake is completed, thus won't contain our certs
		// Most likely a cipher change
		// But, if we are in SSL, we have the certs with the hello, so the server name will be there
		if !self.isTLS() {
			Logger().Debug("Dealing with non-TLS exchange. Getting server name from server hello")
			self.serverName = server_hello.serverName
		} else {
			cert_exchange := &TLSPacket{}
			cert_exchange.Parse(buf)
		}

	} else if self.handshakeType == 11 {
		Logger().Debug("Found cert exchange")
		cert_exchange := &TLSServerCertExchange{}
		cert_exchange.Parse(self, buf)
		self.serverName = cert_exchange.serverName
	}

}

func ParseHTTPS(packet *util.Packet) *base.Destination {
	Logger().Debug(packet.Hosts, packet.Ports)
	buf := bytes.NewBuffer(packet.Payload)
	tlsPacket := &TLSPacket{}
	tlsPacket.Parse(buf)
	if tlsPacket.serverName != "" {
		return base.NewDestination(tlsPacket.serverName, packet.Hosts.Src().String(), packet.Hosts.Dst().String())
	}
	return nil
}
