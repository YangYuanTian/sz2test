package pcap

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"sync/atomic"
	"time"
)

type PacketHeaderConfig struct {
	SrcIP        net.IP
	DstIP        net.IP
	SrcPort      layers.UDPPort
	DstPort      layers.UDPPort
	SrcSCTPPort  layers.SCTPPort
	DstSCTPPort  layers.SCTPPort
	SrcTCPTPPort layers.TCPPort
	DstTCPPort   layers.TCPPort
	SrcMac       []byte
	DstMac       []byte
}

var defaultPacketSize = 300

// NewPacketForUDP 构造包，使用应用层对应用层数据进行包装
func NewPacketForUDP(data []byte, config *PacketHeaderConfig) ([]byte, error) {
	if config == nil {
		config = &PacketHeaderConfig{}
	}
	//初始化一个SerializeBuffer对象，把data数据存储进去
	buf := gopacket.NewSerializeBufferExpectedSize(defaultPacketSize, 0)
	//todo 填充应用层消息
	bytes, err := buf.PrependBytes(len(data))
	if err != nil {
		return nil, err
	}
	bytes = bytes[0:0]             //清空容量
	bytes = append(bytes, data...) //添加应用层数据
	//todo 填充udp层的信息
	//构造一个udp结构体，初始化一些基本的信息
	udp := &layers.UDP{
		SrcPort: config.SrcPort,
		DstPort: config.DstPort,
	}
	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err = udp.SerializeTo(buf, opt)
	if err != nil {
		return nil, err
	}
	bufdata, err := FillIPMACLayer(buf, config, opt, layers.IPProtocolUDP)
	if err != nil {
		return nil, err
	}
	return bufdata, nil
}

type packetBytes interface {
	Marshal() ([]byte, error)
}

func NewPacketForPFCP(data []byte) ([]byte, error) {
	config := &PacketHeaderConfig{}
	config.DstPort = 8805
	config.SrcPort = 8805
	data, err := NewPacketForUDP(data, config)
	if err != nil {
		return nil, err
	}
	return data, nil
}

var conut uint32

func getSequence() uint32 {
	return atomic.AddUint32(&conut, 1)
}

// NewPacketForSCTP 构造包，使用应用层对应用层数据进行包装
func NewPacketForSCTP(data []byte, config *PacketHeaderConfig) ([]byte, error) {
	if config == nil {
		config = &PacketHeaderConfig{}
	}
	//初始化一个SerializeBuffer对象，把data数据存储进去
	buf := gopacket.NewSerializeBufferExpectedSize(defaultPacketSize, 0)
	//todo 填充NGAP消息
	bytes, err := buf.PrependBytes(len(data))
	if err != nil {
		return nil, err
	}
	bytes = bytes[0:0]             //清空容量
	bytes = append(bytes, data...) //添加应用层数据
	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	//todo 填充数据块的内容
	chunk := layers.SCTPData{
		BeginFragment:   true,
		EndFragment:     true,
		PayloadProtocol: 60,
		TSN:             getSequence(),
	}
	err = chunk.SerializeTo(buf, opt)
	if err != nil {
		return nil, err
	}
	//todo 填充SCTP层的信息
	//构造一个udp结构体，初始化一些基本的信息
	udp := &layers.SCTP{
		SrcPort:         config.SrcSCTPPort,
		DstPort:         config.DstSCTPPort,
		VerificationTag: binary.BigEndian.Uint32([]byte{0x42, 0xf7, 0xe9, 0x44}),
	}
	err = udp.SerializeTo(buf, opt)
	if err != nil {
		return nil, err
	}
	bufdata, err := FillIPMACLayer(buf, config, opt, layers.IPProtocolSCTP)
	if err != nil {
		return nil, err
	}
	return bufdata, nil
}

func FillIPMACLayer(buf gopacket.SerializeBuffer, config *PacketHeaderConfig, opt gopacket.SerializeOptions, msgType layers.IPProtocol) ([]byte, error) {
	//todo 填充ip层的信息
	var ipv4flag, ipv6flag bool
	var ipv4 *layers.IPv4
	var ipv6 *layers.IPv6
	if len(config.SrcIP) == 4 || len(config.DstIP) == 4 || (len(config.SrcIP) == 0 && len(config.DstIP) == 0) { //没有填充ip默认是ipv4类型
		if len(config.SrcIP) == 0 {
			config.SrcIP = []byte{0, 0, 0, 0}
		}
		if len(config.DstIP) == 0 {
			config.DstIP = []byte{0, 0, 0, 0}
		}
		ipv4 = &layers.IPv4{
			Version:  4,
			TTL:      128,
			Protocol: msgType,
			SrcIP:    config.SrcIP,
			DstIP:    config.DstIP,
		}
		ipv4flag = true
	} else if len(config.SrcIP) == 16 || len(config.DstIP) == 16 {
		if len(config.SrcIP) == 0 {
			config.SrcIP = make([]byte, 16, 16)
		}
		if len(config.DstIP) == 0 {
			config.DstIP = make([]byte, 16, 16)
		}
		ipv6 = &layers.IPv6{
			Version:    6,
			HopLimit:   128,
			NextHeader: msgType,
			SrcIP:      config.SrcIP,
			DstIP:      config.DstIP,
		}
		ipv6flag = true
	} else {
		return nil, fmt.Errorf("ip length error")
	}
	var ethtype layers.EthernetType
	if ipv4flag {
		err := ipv4.SerializeTo(buf, opt)
		if err != nil {
			return nil, err
		}
		ethtype = layers.EthernetTypeIPv4
	} else if ipv6flag {
		err := ipv6.SerializeTo(buf, opt)
		if err != nil {
			return nil, err
		}
		ethtype = layers.EthernetTypeIPv6
	} else {
		return nil, fmt.Errorf("ip version error")
	}
	//todo 填充mac层的信息
	if len(config.SrcMac) == 0 {
		config.SrcMac = make([]byte, 6)
	}
	if len(config.DstMac) == 0 {
		config.DstMac = make([]byte, 6)
	}
	ethernet := layers.Ethernet{
		SrcMAC:       config.SrcMac,
		DstMAC:       config.DstMac,
		EthernetType: ethtype,
	}
	err := ethernet.SerializeTo(buf, opt)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NewPacketForTCP 构造包，使用应用层对应用层数据进行包装
func NewPacketForTCP(data []byte, config *PacketHeaderConfig) ([]byte, error) {
	if config == nil {
		config = &PacketHeaderConfig{}
	}
	//初始化一个SerializeBuffer对象，把data数据存储进去
	buf := gopacket.NewSerializeBufferExpectedSize(defaultPacketSize, 0)
	//todo 填充应用层消息
	bytes, err := buf.PrependBytes(len(data))
	if err != nil {
		return nil, err
	}
	bytes = bytes[0:0]             //清空容量
	bytes = append(bytes, data...) //添加应用层数据
	//todo 填充tcp层的信息
	//构造一个udp结构体，初始化一些基本的信息
	tcp := &layers.TCP{
		SrcPort: config.SrcTCPTPPort,
		DstPort: config.DstTCPPort,
		Window:  400,
	}
	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err = tcp.SerializeTo(buf, opt)
	if err != nil {
		return nil, err
	}
	bufdata, err := FillIPMACLayer(buf, config, opt, layers.IPProtocolTCP)
	if err != nil {
		return nil, err
	}
	return bufdata, nil
}

func NewPacketForHTTP(data string) ([]byte, error) {
	config := &PacketHeaderConfig{SrcTCPTPPort: 29513, DstTCPPort: 29513}
	tcp, err := NewPacketForTCP([]byte(data), config)
	if err != nil {
		return nil, err
	}
	return tcp, err
}

func NewPacketForNGAP(data []byte) ([]byte, error) {
	return NewPacketForSCTP(data, &PacketHeaderConfig{
		SrcSCTPPort: 38412,
		DstSCTPPort: 38412,
	})
}

type PcapGlobalHear struct {
	Magic    uint32 //：4Byte：标记文件开始，并用来识别文件自己和字节顺序。0xa1b2c3d4用来表示按照原来的顺序读取，0xd4c3b2a1表示下面的字节都要交换顺序读取。考虑到计算机内存的存储结构，一般会采用0xd4c3b2a1，即所有字节都需要交换顺序读取。
	Major    uint16 //：2Byte： 当前文件主要的版本号，一般为 0x0200【实际上因为需要交换读取顺序，所以计算机看到的应该是 0x0002】
	Minor    uint16 //：2Byte： 当前文件次要的版本号，一般为 0x0400【计算机看到的应该是 0x0004】
	ThisZone uint32 //：4Byte：当地的标准时间，如果用的是GMT则全零，一般都直接写
	SigFigs  uint32 //：4Byte：时间戳的精度，设置为 全零 即可
	SnapLen  uint32 //：4Byte：最大的存储长度，如果想把整个包抓下来，设置为 ，但一般来说 ff7f 0000就足够了【计算机看到的应该是 0000 ff7f 】
	LinkType uint32 //：4Byte：链路类型  以太网或者环路类型为
}

func (h *PcapGlobalHear) SetDefault() *PcapGlobalHear {
	h.Magic = 0xa1b2c3d4
	h.Major = 0x0002
	h.Minor = 0x0004
	h.SnapLen = 0x0000ff7f
	h.LinkType = 1
	return h
}
func (h *PcapGlobalHear) Marshal() []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], h.Magic)
	binary.LittleEndian.PutUint16(buf[4:6], h.Major)
	binary.LittleEndian.PutUint16(buf[6:8], h.Minor)
	binary.LittleEndian.PutUint32(buf[8:12], h.ThisZone)
	binary.LittleEndian.PutUint32(buf[12:16], h.SigFigs)
	binary.LittleEndian.PutUint32(buf[16:20], h.SnapLen)
	binary.LittleEndian.PutUint32(buf[20:24], h.LinkType)
	return buf
}
func (h *PcapGlobalHear) UnMarshal(buf []byte) error {
	if len(buf) != 24 {
		return fmt.Errorf("buffer len error,unmarshal failed")
	}
	h.Magic = binary.LittleEndian.Uint32(buf[0:4])
	h.Major = binary.LittleEndian.Uint16(buf[4:6])
	h.Minor = binary.LittleEndian.Uint16(buf[6:8])
	h.ThisZone = binary.LittleEndian.Uint32(buf[8:12])
	h.SigFigs = binary.LittleEndian.Uint32(buf[12:16])
	h.SnapLen = binary.LittleEndian.Uint32(buf[16:20])
	h.LinkType = binary.LittleEndian.Uint32(buf[20:24])
	return nil
}

type PacketHeader struct {
	TimestampH uint32 //：被捕获时间的高位，单位是seconds
	TimestampL uint32 //：被捕获时间的低位，单位是microseconds
	CapLen     uint32 //：当前数据区的长度，即抓取到的数据帧长度，不包括Packet Header本身的长度，单位是 Byte ，由此可以得到下一个数据帧的位置。
	Len        uint32 //：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
}

func (p *PacketHeader) Marshal() []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], p.TimestampH)
	binary.LittleEndian.PutUint32(buf[4:8], p.TimestampL)
	binary.LittleEndian.PutUint32(buf[8:12], p.CapLen)
	binary.LittleEndian.PutUint32(buf[12:16], p.Len)
	return buf
}
func (p *PacketHeader) UnMarshal(b []byte) error {
	if len(b) != 16 {
		return fmt.Errorf("length bytes should be 16,rather than %d", len(b))
	}
	p.TimestampH = binary.LittleEndian.Uint32(b[0:4])
	p.TimestampL = binary.LittleEndian.Uint32(b[4:8])
	p.CapLen = binary.LittleEndian.Uint32(b[8:12])
	p.Len = binary.LittleEndian.Uint32(b[12:16])
	return nil
}

func (p *PacketHeader) Packing(packets []byte) []byte {
	p.Len = uint32(len(packets))
	if len(packets) > 0xffffffff {
		return nil
	}
	p.CapLen = p.Len
	t2 := time.Now().UnixNano()
	p.TimestampH = uint32(t2 / 1e9)       //单位是s
	p.TimestampL = uint32(t2 % 1e9 / 1e3) //单位是ms
	pac := make([]byte, 0, 0)
	pac = append(pac, p.Marshal()...)
	pac = append(pac, packets...)
	return pac
}

func NewUDPPacket(Data []byte, Port uint16) []byte {
	var port = make([]byte, 2, 2)
	binary.BigEndian.PutUint16(port, Port)
	//ip                                          ps            pd
	head := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa4, 0x16, 0xe7, 0x7c, 0xf5, 0x1e, 0x08, 0x00, 0x45, 0xc0, 0x01, 0x71, 0x44, 0xfd, 0x00, 0x00, 0xff, 0x11, 0x74, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, port[0], port[1], port[0], port[1], 0x01, 0x5d, 0x00, 0x00}
	ipLen := 16
	udpLen := 38
	data := Data
	dataLen := uint16(len(data) + 8)
	buf := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(buf[0:2], dataLen)
	head[udpLen] = buf[0]
	head[udpLen+1] = buf[1]
	binary.BigEndian.PutUint16(buf[0:2], dataLen+20)
	head[ipLen] = buf[0]
	head[ipLen+1] = buf[1]
	return append(head, data...)
}
