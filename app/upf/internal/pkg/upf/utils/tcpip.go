package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type BaseLayer struct {
	// Contents is the set of bytes that make up this layer.  IE: for an
	// Ethernet packet, this would be the set of bytes making up the
	// Ethernet frame.
	Contents []byte
	// Payload is the set of bytes contained by (but not part of) this
	// Layer.  Again, to take Ethernet as an example, this would be the
	// set of bytes encapsulated by the Ethernet protocol.
	Payload []byte
}

// TCP is the layer for TCP headers.
type TCP struct {
	BaseLayer
	SrcPort, DstPort                           TCPPort
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	sPort, dPort                               []byte
	Options                                    []TCPOption
	Padding                                    []byte
	opts                                       [4]TCPOption
	//tcpipchecksum
}

type TCPOption struct {
	OptionType   TCPOptionKind
	OptionLength uint8
	OptionData   []byte
}

// TCPOptionKind represents a TCP option code.
type TCPOptionKind uint8

const (
	TCPOptionKindEndList                         = 0
	TCPOptionKindNop                             = 1
	TCPOptionKindMSS                             = 2  // len = 4
	TCPOptionKindWindowScale                     = 3  // len = 3
	TCPOptionKindSACKPermitted                   = 4  // len = 2
	TCPOptionKindSACK                            = 5  // len = n
	TCPOptionKindEcho                            = 6  // len = 6, obsolete
	TCPOptionKindEchoReply                       = 7  // len = 6, obsolete
	TCPOptionKindTimestamps                      = 8  // len = 10
	TCPOptionKindPartialOrderConnectionPermitted = 9  // len = 2, obsolete
	TCPOptionKindPartialOrderServiceProfile      = 10 // len = 3, obsolete
	TCPOptionKindCC                              = 11 // obsolete
	TCPOptionKindCCNew                           = 12 // obsolete
	TCPOptionKindCCEcho                          = 13 // obsolete
	TCPOptionKindAltChecksum                     = 14 // len = 3, obsolete
	TCPOptionKindAltChecksumData                 = 15 // len = n, obsolete
)

func (tcp *TCP) DecodeFromBytes(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("Invalid TCP header. Length %d less than 20", len(data))
	}
	tcp.SrcPort = TCPPort(binary.BigEndian.Uint16(data[0:2]))
	tcp.sPort = data[0:2]
	tcp.DstPort = TCPPort(binary.BigEndian.Uint16(data[2:4]))
	tcp.dPort = data[2:4]
	tcp.Seq = binary.BigEndian.Uint32(data[4:8])
	tcp.Ack = binary.BigEndian.Uint32(data[8:12])
	tcp.DataOffset = data[12] >> 4
	tcp.FIN = data[13]&0x01 != 0
	tcp.SYN = data[13]&0x02 != 0
	tcp.RST = data[13]&0x04 != 0
	tcp.PSH = data[13]&0x08 != 0
	tcp.ACK = data[13]&0x10 != 0
	tcp.URG = data[13]&0x20 != 0
	tcp.ECE = data[13]&0x40 != 0
	tcp.CWR = data[13]&0x80 != 0
	tcp.NS = data[12]&0x01 != 0
	tcp.Window = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(data[18:20])
	if tcp.Options == nil {
		// Pre-allocate to avoid allocating a slice.
		tcp.Options = tcp.opts[:0]
	} else {
		tcp.Options = tcp.Options[:0]
	}
	if tcp.DataOffset < 5 {
		return fmt.Errorf("Invalid TCP data offset %d < 5", tcp.DataOffset)
	}
	dataStart := int(tcp.DataOffset) * 4
	if dataStart > len(data) {
		tcp.Payload = nil
		tcp.Contents = data
		return errors.New("TCP data offset greater than packet length")
	}
	tcp.Contents = data[:dataStart]
	tcp.Payload = data[dataStart:]
	// From here on, data points just to the header options.
	data = data[20:dataStart]
	for len(data) > 0 {
		tcp.Options = append(tcp.Options, TCPOption{OptionType: TCPOptionKind(data[0])})
		opt := &tcp.Options[len(tcp.Options)-1]
		switch opt.OptionType {
		case TCPOptionKindEndList: // End of options
			opt.OptionLength = 1
			tcp.Padding = data[1:]
			break
		case TCPOptionKindNop: // 1 byte padding
			opt.OptionLength = 1
		default:
			if len(data) < 2 {
				return fmt.Errorf("Invalid TCP option length. Length %d less than 2", len(data))
			}
			opt.OptionLength = data[1]
			if opt.OptionLength < 2 {
				return fmt.Errorf("Invalid TCP option length %d < 2", opt.OptionLength)
			} else if int(opt.OptionLength) > len(data) {
				return fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.OptionLength, len(data))
			}
			opt.OptionData = data[2:opt.OptionLength]
		}
		data = data[opt.OptionLength:]
	}
	return nil
}

func (tcp *TCP) PartialDecodeFromBytes(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("Invalid TCP header. Length %d less than 20", len(data))
	}
	tcp.SrcPort = TCPPort(binary.BigEndian.Uint16(data[0:2]))
	tcp.DstPort = TCPPort(binary.BigEndian.Uint16(data[2:4]))

	return nil
}
