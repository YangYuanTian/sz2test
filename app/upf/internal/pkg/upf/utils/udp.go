package utils

import (
	"encoding/binary"
	"fmt"
)

// UDP is the layer for UDP headers.
type UDP struct {
	BaseLayer
	SrcPort, DstPort UDPPort
	Length           uint16
	Checksum         uint16
	sPort, dPort     []byte
}

func (udp *UDP) DecodeFromBytes(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("Invalid UDP header. Length %d less than 8", len(data))
	}
	udp.SrcPort = UDPPort(binary.BigEndian.Uint16(data[0:2]))
	udp.sPort = data[0:2]
	udp.DstPort = UDPPort(binary.BigEndian.Uint16(data[2:4]))
	udp.dPort = data[2:4]
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])
	udp.BaseLayer = BaseLayer{Contents: data[:8]}
	switch {
	case udp.Length >= 8:
		hlen := int(udp.Length)
		if hlen > len(data) {
			hlen = len(data)
		}
		udp.Payload = data[8:hlen]
	case udp.Length == 0: // Jumbogram, use entire rest of data
		udp.Payload = data[8:]
	default:
		return fmt.Errorf("UDP packet too small: %d bytes", udp.Length)
	}
	return nil
}

// Partial
func (udp *UDP) PartialDecodeFromBytes(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("Invalid UDP header. Length %d less than 8", len(data))
	}
	udp.SrcPort = UDPPort(binary.BigEndian.Uint16(data[0:2]))
	udp.DstPort = UDPPort(binary.BigEndian.Uint16(data[2:4]))

	return nil
}
