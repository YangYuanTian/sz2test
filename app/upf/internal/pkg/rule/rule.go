package rule

import (
	"context"
	"github.com/cilium/ebpf"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"upf/internal/pkg/utils"
)

type Desc uint8

var log = glog.New()

const (
	CreateGTPHeader Desc = iota + 1
	RemoveGTPHeader
)

type Rule struct {
	DropForGateControl bool
	DropForTest        bool

	PassForTest    bool
	PassForSample  bool
	PassForGetRule bool //last bit
	PassForPaging  bool

	StatID      uint16
	DescAction  Desc
	FlowControl uint8
	HeaderLen   uint8
}

// flags
// #define DROP(x) ((x>>56) & 0xff)
// #define PASS(x) ((x>>48) & 0xff)
// #define FLOW_CONTROL(x) ((x>>40) & 0xff)
// #define DESC(x) ((x>>32) & 0xff)
// #define STAT_ID(x) ((x>>16) & 0xffff)
// #define HEADER_LEN(x) ((x>>8) & 0xff)
func (r *Rule) flags() uint64 {

	drop := utils.Bool2byte(r.DropForGateControl)<<7 |
		utils.Bool2byte(r.DropForTest)<<6

	pass := utils.Bool2byte(r.PassForTest)<<5 |
		utils.Bool2byte(r.PassForSample)<<4 |
		utils.Bool2byte(r.PassForGetRule)<<3 |
		utils.Bool2byte(r.PassForPaging)<<2

	f := uint64(drop)<<56 |
		uint64(pass)<<48 |
		uint64(r.FlowControl)<<40 |
		uint64(r.DescAction)<<32 |
		uint64(r.StatID)<<16 |
		uint64(r.HeaderLen)<<8

	return f
}

// ULRule 与ebpf的map关联在一起，当更新结构体里面的内容的时候，
// 会自动更新xdp map里面的内容,使用结构体的详细字段进行编程当然更友好
type ULRule struct {
	Map *ebpf.Map
	Key uint32
	Rule
}

func (r *ULRule) Update(flag ebpf.MapUpdateFlags) error {
	bpf := bpfUsrCtxUplinkT{
		Flags: r.flags(),
	}
	log.Debugf(nil, "store rule %x", bpf.Flags)
	log.Debugf(nil, "store rule %d", bpf.Flags)
	return r.Map.Update(&r.Key, &bpf, flag)
}

func (r *DLRule) Update(flag ebpf.MapUpdateFlags) error {
	ctx := context.Background()

	options := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(
		buffer,
		options,
		r.Layers()...,
	)

	if err != nil {
		return gerror.Wrap(err, "serialize layers failed")
	}

	outgoingPacket := buffer.Bytes()

	if len(outgoingPacket) > 48 {
		return gerror.New("packet length is too long")
	}

	r.Rule.HeaderLen = uint8(len(outgoingPacket))

	log.Debugf(ctx, "update dl control information")

	log.Debugf(ctx, "template header len:%d", r.Rule.HeaderLen)

	pkt := gopacket.NewPacket(outgoingPacket, layers.LayerTypeIPv4, gopacket.Default)
	log.Debugf(ctx, pkt.Dump())

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

	Rule

	TEID  uint32
	GNBIP net.IP
	SrcIP net.IP
	PPP   bool
	PPI   uint8
	RQI   bool
	QFI   uint8
}

func (d *DLRule) GetExtendHeader() []layers.GTPExtensionHeader {

	c := &pduSessionContainer{
		pduType: 0,
		PPP:     d.PPP,
		RQI:     d.RQI,
		QFI:     d.QFI,
		PPI:     d.PPI,
	}

	h := layers.GTPExtensionHeader{
		Type:    0x85, //pdu session container
		Content: c.Marshal(),
	}

	return []layers.GTPExtensionHeader{h}
}

type pduSessionContainer struct {
	pduType uint8 //8-4 dl session
	PPP     bool  //:8
	RQI     bool  //:7
	QFI     uint8 //:6-1
	PPI     uint8 //8-6
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func (p *pduSessionContainer) Marshal() []byte {
	var b []byte
	b = make([]byte, 2)
	b[0] = p.pduType << 4
	b[1] = boolToUint8(p.PPP)<<7 | boolToUint8(p.RQI)<<6 | p.QFI&0x3f
	if p.PPP {
		b = append(b, p.PPI<<5, 0, 0, 0)
	}

	return b
}

func (r *DLRule) Layers() []gopacket.SerializableLayer {
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
		GTPExtensionHeaders: r.GetExtendHeader(),
	}

	return []gopacket.SerializableLayer{
		ipLayer,
		udpLayer,
		gtpLayer,
	}
}

type bpfUsrCtxDownLinkT struct {
	Template [48]uint8
	Flags    uint64
}

type bpfUsrCtxUplinkT struct{ Flags uint64 }
