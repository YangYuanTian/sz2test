package ipport

import (
	"fmt"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

type NetworkSubnet struct {
	IPv4 types.IPv4Subnet `json:"ipv4"`
	IPv6 types.IPv6Subnet `json:"ipv6"`
}

type IpPort struct {
	Index  uint16        `json:"index"`
	Subnet NetworkSubnet `json:"subnet"`
	//static dst mac
	DstMacAddress types.MACAddress `json:"dst-mac"`

	StaticARP  bool // 配置DstMacAddress，不用查询arp
	NeighCache *packet.NeighboursLookupTable
	// self mac
	MacAddress types.MACAddress

	PacketCount uint64
	BytesCount  uint64
	IsN3Port    bool
}

func (p *IpPort) LookMAC(ip []byte) ([6]byte, bool) {
	return p.NeighCache.LookupMACForIPv4(types.SliceToIPv4(ip))
}

func (p *IpPort) PortID() uint16 {
	return p.Index
}

func (p *IpPort) IPV4Addr() []byte {
	ip := types.IPv4ToBytes(p.Subnet.IPv4.Addr)
	return ip[:]
}

func (p *IpPort) MacAddr() [6]byte {
	return p.MacAddress
}

func (p *IpPort) StorePkt(pkt *packet.Packet) {
	p.NeighCache.SendARPRequestForIPv4(pkt.GetIPv4().DstAddr, pkt.GetIPv4().SrcAddr, 0)
	ARPStore(pkt)
}

func ARPStore(pkt *packet.Packet) {
	// 没有find, 将报文先保存起来，如果缓存中的报文数量超过200个，将旧的释放掉。第一次不加锁是为了性能考虑
	if packet.GArpBuffers.Len() > 200 {
		packet.GArpMutex.Lock()
		if packet.GArpBuffers.Len() > 200 {
			bufferHead := packet.GArpBuffers.Front()
			packet.GArpBuffers.Remove(bufferHead)
			packet.GArpMutex.Unlock()
			oldPacket := bufferHead.Value.(*packet.Packet)
			oldPacket.FreePacket()
		} else {
			packet.GArpMutex.Unlock()
		}
	}
	srcbuf := pkt.GetRawPacketBytes()
	// 从arp buf pool里申请一个mbuf内存缓存起来
	arpPacket, _ := packet.NewArpBufPacket()
	if nil != arpPacket {
		arpbuf := (*[2 << 10]byte)(arpPacket.StartAtOffset(0))
		copy(arpbuf[0:], srcbuf)
		arpPacket.PacketSetDataLen(uint(len(srcbuf)))
		arpPacket.ParseL3()
		arpPacket.SetTXIPv4UDPOLFlags(14, 20)

		packet.GArpMutex.Lock()
		packet.GArpBuffers.PushBack(arpPacket)
		packet.GArpMutex.Unlock()
	}
	return
}
func (p *IpPort) String(index uint16) string {

	tmpStr := fmt.Sprintf("index: %s\n", p.Index)
	tmpStr += fmt.Sprintf("subnet: %s\n", p.Subnet)
	tmpStr += fmt.Sprintf("dst static mac address: %s\n", p.DstMacAddress)
	tmpStr += fmt.Sprintf("mac address: %s\n", p.MacAddress)
	//tmpStr+= fmt.Sprintf("packet count: %s\n", p.PacketCount)

	return tmpStr
}

// n6 context

type IpPortShow struct {
	Index uint16 `json:"index"`
	IPv4  string `json:"ipv4"`
	IPv6  string `json:"ipv6,omitempty"`
	//static dst mac
	StaticDstMacAddress string `json:"static dst mac"`
	StaticARP           bool   `json:"static arp"`
	// self mac
	MacAddress string `json:"self mac"`
	IsN3Port   bool   `json:"is n3 port"`
}

func (p *IpPort) ShowIpPort() *IpPortShow {
	portInfo := &IpPortShow{
		Index:               p.Index,
		IPv4:                p.Subnet.IPv4.String(),
		IPv6:                p.Subnet.IPv6.String(),
		StaticDstMacAddress: p.DstMacAddress.String(),
		StaticARP:           p.StaticARP,
		MacAddress:          p.MacAddress.String(),
		IsN3Port:            p.IsN3Port,
	}
	return portInfo
}
