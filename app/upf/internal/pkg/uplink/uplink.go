package uplink

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

type ULHandler struct {
	N3Port *port.Port
	N6Port *port.Port
}

func (u *ULHandler) MsgHandle(ctx context.Context, msg []byte) error {
	pkt := gopacket.NewPacket(msg, layers.LayerTypeEthernet, gopacket.Default)
	if pkt == nil {
		return nil
	}

	gtp := pkt.Layer(layers.LayerTypeGTPv1U)
	if gtp == nil {
		log.Debugf(ctx, "no gtp layer")
		return nil
	}

	gtpu := gtp.(*layers.GTPv1U)

	usr := user.GetUserById(id.TEID(gtpu.TEID))

	if usr == nil {
		log.Debugf(ctx, "not found user with teid:%d", gtpu.TEID)
		return nil
	}

	//获取对应的规则，并且更新xdp中的缓存
	if err := usr.UpdateUlRule(); err != nil {
		return err
	}

	if usr.ULRule.DescAction != rule.RemoveGTPHeader {
		return nil
	}

	//获取取出gtp之后的数据
	data := gtpu.Payload

	//将数据包发送到n6
	if err := u.N6Port.Send(data); err != nil {
		return err
	}

	return nil
}
