package downlink

import (
	"context"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"upf/internal/pkg/id"
	"upf/internal/pkg/port"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/user"
)

var log = glog.New()

type DLHandler struct {
	N3Port *port.Port
	N6Port *port.Port
	ctx    context.Context
}

func (h *DLHandler) Handle(ctx context.Context, msg []byte) error {

	pkt := gopacket.NewPacket(msg, layers.LayerTypeEthernet, gopacket.Default)
	log.Debug(ctx, "downlink message: %s", pkt)

	l := pkt.Layer(layers.LayerTypeIPv4)
	if l == nil {
		log.Debugf(ctx, "not ipv4 packet")
		return nil
	}

	ip, _ := l.(*layers.IPv4)

	usr := user.GetUserById(id.UEIP(ip.DstIP))

	if usr == nil {
		log.Debugf(ctx, "user not found with ueip %s", ip.DstIP)
		return nil
	}

	if usr.Desc != rule.CreateGTPHeader {
		log.Debugf(ctx, "user opt  %s not create gtp header", usr.Desc)
		return nil
	}

	// create gtp header
	gtp := layers.GTPv1U{
		Version:             1,
		ProtocolType:        1,
		MessageType:         255,
		TEID:                usr.TEID,
		ExtensionHeaderFlag: true,
		GTPExtensionHeaders: usr.GetExtendHeader(),
	}

	//marshal packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	layer := usr.Layers()
	pkt.Layer(layers.LayerTypeEthernet)
	layer = append(layer, pkt.Layers()[1:]...)

	err := gopacket.SerializeLayers(buf, opts, usr.Layers()...)

	return nil
}
