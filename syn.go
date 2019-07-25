package scanner

import (
	"bytes"
	"encoding/binary"
)

const (
	urg = 32 >> iota // 10 0000
	ack              // 01 0000
	psh              // 00 1000
	rst              // 00 0100
	syn              // 00 0010
	fin              // 00 0001
)

type TCPHeader struct {
	Source      uint16
	Destination uint16
	SeqNumber   uint32
	AckNumber   uint32
	Length      uint8 // 4 bits
	Reserved    uint8 // 3 bits
	NCE         uint8 // 3 bits Nonce Congestion ECN-Echo
	CTRL        uint8 // 6 bits URG ACK PSH RST SYN FIN
	WindowSize  uint16
	Checksum    uint16 // kernel will set this if it's 0
	Urgent      uint16
	// no options required
}

func (tcp *TCPHeader) Marshal() []byte {
	// TCP Header size is 20
	buf := bytes.NewBuffer(make([]byte, 0, 20))
	_ = binary.Write(buf, binary.BigEndian, tcp.Source)
	_ = binary.Write(buf, binary.BigEndian, tcp.Destination)
	_ = binary.Write(buf, binary.BigEndian, tcp.SeqNumber)
	_ = binary.Write(buf, binary.BigEndian, tcp.AckNumber)
	// lrnc = Length Reserved NCE CTRL
	var lrnc uint16
	// 5 * 4 = 20 Bytes
	tcp.Length = 5
	lrnc = uint16(tcp.Length)<<12 | // 4 bits
		uint16(tcp.Reserved)<<9 | // 3 bits
		uint16(tcp.NCE)<<6 | // 3 bits
		uint16(tcp.CTRL) // 6 bits
	_ = binary.Write(buf, binary.BigEndian, lrnc)
	_ = binary.Write(buf, binary.BigEndian, tcp.WindowSize)
	_ = binary.Write(buf, binary.BigEndian, tcp.Checksum)
	_ = binary.Write(buf, binary.BigEndian, tcp.Urgent)
	return buf.Bytes()
}

func (tcp *TCPHeader) Unmarshal(data []byte) {
	reader := bytes.NewReader(data)
	_ = binary.Read(reader, binary.BigEndian, &tcp.Source)
	_ = binary.Read(reader, binary.BigEndian, &tcp.Destination)
	_ = binary.Read(reader, binary.BigEndian, &tcp.SeqNumber)
	_ = binary.Read(reader, binary.BigEndian, &tcp.AckNumber)
	var lrnc uint16
	_ = binary.Read(reader, binary.BigEndian, &lrnc)
	tcp.Length = byte(lrnc >> 12)      // 4 bits
	tcp.Reserved = byte(lrnc >> 9 & 7) // 3 bits
	tcp.NCE = byte(lrnc >> 6 & 7)      // 3 bits
	tcp.CTRL = byte(lrnc & 0x3f)       // 6 bits
	_ = binary.Read(reader, binary.BigEndian, &tcp.WindowSize)
	_ = binary.Read(reader, binary.BigEndian, &tcp.Checksum)
	_ = binary.Read(reader, binary.BigEndian, &tcp.Urgent)
}
