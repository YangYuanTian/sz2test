package service

import (
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/am"
	"lite5gc/upf/context/pdrcontext"
	. "lite5gc/upf/defs"
	"lite5gc/upf/service/upfam"
	"net"
)

const moduleTag rlogger.ModuleTag = "service"

// N6 rawsocket server
type rawServer struct {
	MsgListChan [DPE_GOROUTINE_NUMBER]chan MsgCxt // receive msg list
	Ipv4Addr
	Ipv6Addr
	Mac     string
	UpfConf configure.UpfConfig
	GNbIp   net.IP
	// paging
	MsgBuffChan chan MsgCxt
}

// NewRawServer generate object Server channel
func NewRawServer() *rawServer {
	server := &rawServer{}
	for i := 0; i < len(server.MsgListChan); i++ {
		server.MsgListChan[i] = make(chan MsgCxt, RAW_CHAN_CAP)
	}
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "n6 dpe len %d",
		len(server.MsgListChan))
	server.MsgBuffChan = make(chan MsgCxt, RAW_CHAN_CAP)
	//get local ip address TODO 本地无需IP,用于N3 目的IP地址
	server.Ipv4 = net.ParseIP(configure.UpfConf.N3.Ipv4)
	server.Ipv6 = net.ParseIP(configure.UpfConf.N3.Ipv6)
	//server.Port = configure.UpfConf.N3.Port
	//todo
	//server.UpfConf = *configure.UpfConf
	//server.GNbIp = net.ParseIP(configure.UpfConf.N3.Gnb.Ipv4)

	return server
}

// ReceiveMsg Send the received message to the rawsock channel
func (s *rawServer) ReceiveMsg(msg []byte, Msgcxt *pdrcontext.DataFlowContext) bool {
	//rlogger.FuncEntry(moduleTag, nil)
	msgCxt := MsgCxt{Msgbuf: msg,
		Msgcxt: Msgcxt,
	}
	DPENo := IpportdistributeNo(msgCxt.Msgcxt.UEIP, msgCxt.Msgcxt.UEPort)
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "n6 send to dpe no(%d),%s+%d",
		DPENo, msgCxt.Msgcxt.UEIP, msgCxt.Msgcxt.UEPort)
	select {
	case s.MsgListChan[DPENo] <- msgCxt:
		return true
	default:
		return false //队列已满，消息丢弃
	}
}

// ReceiveBuffMsg Send the received message to the MsgBuffChan channel
func (s *rawServer) ReceiveBuffMsg(msg []byte, Msgcxt *pdrcontext.DataFlowContext) bool {
	//rlogger.FuncEntry()
	msgCxt := MsgCxt{Msgbuf: msg,
		Msgcxt: Msgcxt,
	}
	select {
	case s.MsgBuffChan <- msgCxt:
		return true
	default:
		//todo 用户去激活时，缓存池满，丢包时产生特定用户的告警
		userPackerBuffer, _ := upfam.UserPackerBuffer.Get(Msgcxt.SEID)
		if !userPackerBuffer {
			ip, _ := upfam.DateGateControlDL.Get(Msgcxt.SEID)
			alarmDetails := upfam.UPFAlarmDetails{
				AlarmID:   am.UserPacketBufferOverFlow,
				Reason:    "user's packet loss:buffer overflow when deactivation",
				Substring: ip,
			}
			upfam.UPFAlarmReport(alarmDetails) //用户缓存区溢出丢包告警
			upfam.UserPackerBuffer.Add(Msgcxt.SEID, true)
		}
		return false //队列已满，消息丢弃
	}
}
