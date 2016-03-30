package util

import (
	"bytes"
	"encoding/binary"
	"github.com/google/gopacket"
)

type Packet struct {
	Hosts   gopacket.Flow
	Ports   gopacket.Flow
	Payload []byte
}

func ReadBigEndian16(buf *bytes.Buffer) uint16 {
	var x uint16
	binary.Read(buf, binary.BigEndian, &x)
	return x
}

func ReadBigEndian24(buf *bytes.Buffer) uint32 {
	threeBytesEndian := buf.Next(3)
	fourBytesEndian := append([]byte{0}, threeBytesEndian...)
	tmpBuf := bytes.NewBuffer(fourBytesEndian)

	var x uint32
	binary.Read(tmpBuf, binary.BigEndian, &x)
	return x
}

func ReadUint8(buf *bytes.Buffer) uint8 {
	return uint8(buf.Next(1)[0])
}
