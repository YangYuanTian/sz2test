package downlink

import (
	"context"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"upf/internal/pkg/id"
	"upf/internal/pkg/pktinfo"
	"upf/internal/pkg/port"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/user"
)

var log = glog.New()

type DLHandler struct {
	N3Port *port.Port
	N6Port *port.Port
}

func (h *DLHandler) MsgHandle(ctx context.Context, msg []byte) error {

	pkt := gopacket.NewPacket(msg, layers.LayerTypeEthernet, gopacket.Default)
	log.Debug(ctx, "downlink message: %s", pkt)

	l := pkt.Layer(layers.LayerTypeIPv4)
	if l == nil {
		log.Debugf(ctx, "not ipv4 packet")
		return nil
	}

	ip, _ := l.(*layers.IPv4)

	usr := user.GetUserById(id.UEIP(ip.DstIP).String())

	if usr == nil {
		log.Debugf(ctx, "user not found with ueip %s", ip.DstIP)
		return nil
	}

	if err := usr.UpdateDlRule(&pktinfo.DlPkt{}); err != nil {
		log.Debugf(ctx, "update dl rule failed: %s", err)
		return nil
	}

	if usr.DLRule.DescAction != rule.CreateGTPHeader {
		log.Debugf(ctx, "user opt  %s not create gtp header", usr.DLRule.DescAction)
		return nil
	}

	//marshal packet
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	layer := usr.Layers()

	layer = append(layer, gopacket.Payload(pkt.Layers()[0].LayerPayload()))

	err := gopacket.SerializeLayers(buf, opts, layer...)
	if err != nil {
		log.Debugf(ctx, "serialize layers failed: %s", err)
		return nil
	}

	//send packet
	if err := h.N3Port.Send(buf.Bytes()); err != nil {
		log.Errorf(ctx, "send packet error: %s", err)
		return err
	}

	return nil
}
