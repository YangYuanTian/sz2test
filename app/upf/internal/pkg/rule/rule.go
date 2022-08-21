package rule

import (
	"github.com/cilium/ebpf"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

type rule struct {
	DropForGateControl bool
	DropForTest        bool

	PassForTest    bool
	PassForSample  bool
	PassForGetRule bool

	StatID      uint16
	Desc        uint8
	FlowControl uint8
	HeaderLen   uint8
}

func (r *rule) flags() uint64 {
	return 0
}

//ULRule 与ebpf的map关联在一起，当更新结构体里面的内容的时候，
//会自动更新xdp map里面的内容,使用结构体的详细字段进行编程当然更友好
type ULRule struct {
	Map *ebpf.Map
	Key uint32
	rule
}

func (r *ULRule) Update(flag ebpf.MapUpdateFlags) error {
	bpf := &bpfUsrCtxUplinkT{
		Flags: r.flags(),
	}

	return r.Map.Update(r.Key, bpf, flag)
}

func (r *DLRule) Update(flag ebpf.MapUpdateFlags) error {

	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolUDP,
		IHL:      0x45,
		TTL:      0x80,
		Id:       0x1234,
		SrcIP:    r.SrcIP,
		DstIP:    r.GNBIP,
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(2152),
		DstPort: layers.UDPPort(2152),
	}

	gtpLayer := &layers.GTPv1U{
		Version:             1,
		ProtocolType:        1,
		ExtensionHeaderFlag: true,
		MessageType:         255,
		TEID:                r.TEID,
		GTPExtensionHeaders: nil,
	}

	options := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options,
		ipLayer,
		udpLayer,
		gtpLayer,
	)

	if err != nil {
		return gerror.Wrap(err, "serialize layers failed")
	}

	outgoingPacket := buffer.Bytes()

	if len(outgoingPacket) > 48 {
		return gerror.New("packet length is too long")
	}

	var template [48]byte
	copy(template[:], outgoingPacket)

	bpf := &bpfUsrCtxDownLinkT{
		Template: template,
		Flags:    r.flags(),
	}

	return r.Map.Update(r.Key, bpf, flag)
}

type DLRule struct {
	Map *ebpf.Map
	Key uint32

	rule

	TEID  uint32
	GNBIP net.IP
	SrcIP net.IP
	PPP   bool
	PPI   bool
	QFI   uint8
}

type bpfUsrCtxDownLinkT struct {
	Template [48]uint8
	Flags    uint64
}

type bpfUsrCtxUplinkT struct{ Flags uint64 }
