package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"lite5gc/upf/cp/pdr"
	"net"
)

type IPv4Flag uint8

const (
	IPv4EvilBit       IPv4Flag = 1 << 2 // http://tools.ietf.org/html/rfc3514 ;)
	IPv4DontFragment  IPv4Flag = 1 << 1
	IPv4MoreFragments IPv4Flag = 1 << 0
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIPv4            IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolOSPF            IPProtocol = 89
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolVRRP            IPProtocol = 112
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137
)

type IPv4Option struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

// IPv4 is the header of an IP packet.
type IPv4 struct {
	BaseLayer
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      IPv4Flag
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []IPv4Option
	Padding    []byte
}

// IPv6 is the header of an IP packet.
type IPv6 struct {
	BaseLayer
	VtcFlow    uint32 // IP version, traffic class & flow label
	PayloadLen uint16 // IP packet length - includes sizeof(ip_header)
	Proto      uint8  // Protocol, next header
	HopLimits  uint8  // Hop limits
	SrcAddr    net.IP // IP address of source host
	DstAddr    net.IP // IP address of destination host(s)
}

// DecodeFromBytes decodes the given bytes into this layer.
func (ip *IPv4) DecodeFromBytes(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("Invalid ip4 header. Length %d less than 20", len(data))
	}
	flagsfrags := binary.BigEndian.Uint16(data[6:8])

	ip.Version = uint8(data[0]) >> 4
	ip.IHL = uint8(data[0]) & 0x0F
	ip.TOS = data[1]
	ip.Length = binary.BigEndian.Uint16(data[2:4])
	ip.Id = binary.BigEndian.Uint16(data[4:6])
	ip.Flags = IPv4Flag(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.TTL = data[8]
	ip.Protocol = IPProtocol(data[9])
	ip.Checksum = binary.BigEndian.Uint16(data[10:12])
	ip.SrcIP = data[12:16]
	ip.DstIP = data[16:20]
	ip.Options = ip.Options[:0]
	ip.Padding = nil
	// SetDescription up an initial guess for contents/payload... we'll reset these soon.
	ip.BaseLayer = BaseLayer{Contents: data}

	// This code is added for the following enviroment:
	// * Windows 10 with TSO option activated. ( tested on Hyper-V, RealTek ethernet driver )
	if ip.Length == 0 {
		// If using TSO(TCP Segmentation Offload), length is zero.
		// The actual packet length is the length of data.
		ip.Length = uint16(len(data))
	}

	if ip.Length < 20 {
		return fmt.Errorf("Invalid (too small) IP length (%d < 20)", ip.Length)
	} else if ip.IHL < 5 {
		return fmt.Errorf("Invalid (too small) IP header length (%d < 5)", ip.IHL)
	} else if int(ip.IHL*4) > int(ip.Length) {
		return fmt.Errorf("Invalid IP header length > IP length (%d > %d)", ip.IHL, ip.Length)
	}
	if cmp := len(data) - int(ip.Length); cmp > 0 {
		data = data[:ip.Length]
	} else if cmp < 0 {
		if int(ip.IHL)*4 > len(data) {
			return errors.New("Not all IP header bytes available")
		}
	}
	ip.Contents = data[:ip.IHL*4]
	ip.Payload = data[ip.IHL*4:]
	// From here on, data contains the header options.
	data = data[20 : ip.IHL*4]
	// Pull out IP options
	for len(data) > 0 {
		if ip.Options == nil {
			// Pre-allocate to avoid growing the slice too much.
			ip.Options = make([]IPv4Option, 0, 4)
		}
		opt := IPv4Option{OptionType: data[0]}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			ip.Options = append(ip.Options, opt)
			ip.Padding = data[1:]
			return nil
		case 1: // 1 byte padding
			opt.OptionLength = 1
			data = data[1:]
			ip.Options = append(ip.Options, opt)
		default:
			if len(data) < 2 {
				return fmt.Errorf("Invalid ip4 option length. Length %d less than 2", len(data))
			}
			opt.OptionLength = data[1]
			if len(data) < int(opt.OptionLength) {
				return fmt.Errorf("IP option length exceeds remaining IP header size, option type %v length %v", opt.OptionType, opt.OptionLength)
			}
			if opt.OptionLength <= 2 {
				return fmt.Errorf("Invalid IP option type %v length %d. Must be greater than 2", opt.OptionType, opt.OptionLength)
			}
			opt.OptionData = data[2:opt.OptionLength]
			data = data[opt.OptionLength:]
			ip.Options = append(ip.Options, opt)
		}
	}
	return nil
}
func (ip *IPv4) PartialDecodeFromBytes(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("Invalid ip4 header. Length %d less than 20", len(data))
	}

	ip.Version = uint8(data[0]) >> 4
	ip.IHL = uint8(data[0]) & 0x0F
	ip.TOS = data[1]
	ip.Length = binary.BigEndian.Uint16(data[2:4])
	ip.Protocol = IPProtocol(data[9])
	ip.SrcIP = data[12:16]
	ip.DstIP = data[16:20]

	// SetDescription up an initial guess for contents/payload... we'll reset these soon.
	ip.BaseLayer = BaseLayer{Contents: data}

	// This code is added for the following enviroment:
	// * Windows 10 with TSO option activated. ( tested on Hyper-V, RealTek ethernet driver )
	if ip.Length == 0 {
		// If using TSO(TCP Segmentation Offload), length is zero.
		// The actual packet length is the length of data.
		ip.Length = uint16(len(data))
	}

	if ip.Length < 20 {
		return fmt.Errorf("Invalid (too small) IP length (%d < 20)", ip.Length)
	} else if ip.IHL < 5 {
		return fmt.Errorf("Invalid (too small) IP header length (%d < 5)", ip.IHL)
	} else if int(ip.IHL*4) > int(ip.Length) {
		return fmt.Errorf("Invalid IP header length > IP length (%d > %d)", ip.IHL, ip.Length)
	}
	if cmp := len(data) - int(ip.Length); cmp > 0 {
		data = data[:ip.Length]
	} else if cmp < 0 {
		if int(ip.IHL)*4 > len(data) {
			return errors.New("Not all IP header bytes available")
		}
	}
	ip.Contents = data[:ip.IHL*4]
	ip.Payload = data[ip.IHL*4:]

	return nil
}

func (ip *IPv6) PartialDecodeFromBytes(data []byte) error {
	if len(data) < 40 {
		return fmt.Errorf("Invalid ip6 header. Length %d less than 40", len(data))
	}
	ip.PayloadLen = uint16(data[5]) + uint16(data[4])*256
	ip.Proto = data[6]
	ip.SrcAddr = data[8:24]
	ip.DstAddr = data[24:40]
	ip.Payload = data[40:]
	return nil
}

func (ip *IPv4) pseudoheaderChecksum() (csum uint32, err error) {
	if err := ip.AddressTo4(); err != nil {
		return 0, err
	}
	csum += (uint32(ip.SrcIP[0]) + uint32(ip.SrcIP[2])) << 8
	csum += uint32(ip.SrcIP[1]) + uint32(ip.SrcIP[3])
	csum += (uint32(ip.DstIP[0]) + uint32(ip.DstIP[2])) << 8
	csum += uint32(ip.DstIP[1]) + uint32(ip.DstIP[3])
	return csum, nil
}

func IPv4Byte(ipv4 string) ([4]byte, error) {
	ip := net.ParseIP(ipv4)
	dstIPv4 := [4]byte{}
	if ip == nil {
		return dstIPv4, errors.New("IPv4 format error")
	}
	/*dstIPv4[0] = ip[12]
	dstIPv4[1] = ip[13]
	dstIPv4[2] = ip[14]
	dstIPv4[3] = ip[15]*/
	ip4 := ip.To4()
	copy(dstIPv4[:], ip4)
	//fmt.Printf("%+v\n", dstAddr)
	return dstIPv4, nil
}

func (ip *IPv4) AddressTo4() error {
	var src, dst net.IP

	if addr, err := checkIPv4Address(ip.SrcIP); err != nil {
		return fmt.Errorf("Invalid source IPv4 address (%s)", err)
	} else {
		src = addr
	}
	if addr, err := checkIPv4Address(ip.DstIP); err != nil {
		return fmt.Errorf("Invalid destination IPv4 address (%s)", err)
	} else {
		dst = addr
	}
	ip.SrcIP = src
	ip.DstIP = dst
	return nil
}
func checkIPv4Address(addr net.IP) (net.IP, error) {
	if c := addr.To4(); c != nil {
		return c, nil
	}
	if len(addr) == net.IPv6len {
		return nil, errors.New("address is IPv6")
	}
	return nil, fmt.Errorf("wrong length of %d bytes instead of %d", len(addr), net.IPv4len)
}

func IpFiveTuple(buf []byte) (*pdr.IpPacketHeaderFields, error) {
	// 解析mac头
	//mac := &Header{}
	//mac.ParseHeader(buf[0:14])
	// 解析IP头
	ip4 := &IPv4{}
	err := ip4.PartialDecodeFromBytes(buf) // 全解码 DecodeFromBytes(buf) //(buf[14:])
	if err != nil {
		//fmt.Println("Parse IP header fault")
		return nil, err
	}
	tuple := &pdr.IpPacketHeaderFields{}
	// ip
	tuple.Protocol = byte(ip4.Protocol)
	tuple.DstIp = ip4.DstIP
	tuple.SrcIp = ip4.SrcIP
	// ip total length
	tuple.Length = ip4.Length

	// 解析传输头
	switch IPProtocol(ip4.Protocol) {
	case IPProtocolTCP:
		tcp := &TCP{}
		err := tcp.PartialDecodeFromBytes(ip4.Payload) //(buf[34:])
		if err != nil {
			return nil, err
		}
		tuple.DstPort = int(tcp.DstPort)
		tuple.SrcPort = int(tcp.SrcPort)

	case IPProtocolUDP:
		udp := &UDP{}
		err := udp.PartialDecodeFromBytes(ip4.Payload)
		if err != nil {
			return nil, err
		}
		tuple.DstPort = int(udp.DstPort)
		tuple.SrcPort = int(udp.SrcPort)

	case IPProtocolICMPv4:
		icmp := &ICMPv4{}
		err := icmp.PartialDecodeFromBytes(ip4.Payload)
		if err != nil {
			return nil, err
		}
	default:
		// 其他的IP包，设置默认值0
		tuple.DstPort = 0
		tuple.SrcPort = 0
	}

	return tuple, nil
}

func Ipv6FiveTuple(buf []byte) (*pdr.IpPacketHeaderFields, error) {
	// 解析mac头
	//mac := &Header{}
	//mac.ParseHeader(buf[0:14])
	// 解析IP头
	ip6 := &IPv6{}
	err := ip6.PartialDecodeFromBytes(buf) // 全解码 DecodeFromBytes(buf) //(buf[14:])
	if err != nil {
		//fmt.Println("Parse IP header fault")
		return nil, err
	}
	tuple := &pdr.IpPacketHeaderFields{}
	// ip
	tuple.Protocol = ip6.Proto
	tuple.DstIp = ip6.DstAddr
	tuple.SrcIp = ip6.SrcAddr

	tuple.Length = ip6.PayloadLen + 40 // ip6.PayloadLen + 40(ipv6头部固定长度) = bodylength
	// 解析传输头
	switch IPProtocol(ip6.Proto) {
	case IPProtocolTCP:
		tcp := &TCP{}
		err := tcp.PartialDecodeFromBytes(ip6.Payload) //(buf[54:])
		if err != nil {
			return nil, err
		}
		tuple.DstPort = int(tcp.DstPort)
		tuple.SrcPort = int(tcp.SrcPort)

	case IPProtocolUDP:
		udp := &UDP{}
		err := udp.PartialDecodeFromBytes(ip6.Payload)
		if err != nil {
			return nil, err
		}
		tuple.DstPort = int(udp.DstPort)
		tuple.SrcPort = int(udp.SrcPort)

	default:
		// 其他的IP包，设置默认值0
		tuple.DstPort = 0
		tuple.SrcPort = 0
	}

	return tuple, nil
}

// todo 提升性能
// 单协程适用
type IpVariablePool struct {
	Ip4   IPv4
	tuple pdr.IpPacketHeaderFields
	tcp   TCP
	udp   UDP
	icmp  ICMPv4
}

var ipVaribale IpVariablePool
var ipVaribaleTemp IpVariablePool

func IpFiveTuplePerf(buf []byte) (*pdr.IpPacketHeaderFields, error) {
	// 解析mac头
	//mac := &Header{}
	//mac.ParseHeader(buf[0:14])
	// 解析IP头
	// set null
	ipVaribale = ipVaribaleTemp //todo 全局变量重用问题
	ip4 := &ipVaribale.Ip4
	err := ip4.PartialDecodeFromBytes(buf) // 全解码 DecodeFromBytes(buf) //(buf[14:])
	if err != nil {
		//fmt.Println("Parse IP header fault")
		return nil, err
	}
	tuple := &ipVaribale.tuple
	// ip
	tuple.Protocol = byte(ip4.Protocol)
	tuple.DstIp = ip4.DstIP
	tuple.SrcIp = ip4.SrcIP
	// ip total length
	tuple.Length = ip4.Length
	// 解析传输头
	switch IPProtocol(ip4.Protocol) {
	case IPProtocolTCP:
		tcp := &ipVaribale.tcp
		err := tcp.PartialDecodeFromBytes(ip4.Payload) //(buf[34:])
		if err != nil {
			return nil, err
		}
		tuple.DstPort = int(tcp.DstPort)
		tuple.SrcPort = int(tcp.SrcPort)

	case IPProtocolUDP:
		udp := &ipVaribale.udp
		err := udp.PartialDecodeFromBytes(ip4.Payload)
		if err != nil {
			return nil, err
		}
		tuple.DstPort = int(udp.DstPort)
		tuple.SrcPort = int(udp.SrcPort)

	case IPProtocolICMPv4:
		icmp := &ipVaribale.icmp
		err := icmp.PartialDecodeFromBytes(ip4.Payload)
		if err != nil {
			return nil, err
		}
	default:
		// 其他的IP包，设置默认值0
		tuple.DstPort = 0
		tuple.SrcPort = 0
	}

	return tuple, nil
}
