package defs

import (
	"encoding/binary"
	"lite5gc/cmn/message/gtpv1u"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types/configure"
	"lite5gc/upf/context/pdrcontext"
	"lite5gc/upf/utils"
	"net"
	"sync"
)

const (
	CHANCAP              = 20000 // udp receive channel buffer //1024*3
	DPE_GOROUTINE_NUMBER = 6     //dpe max goroutine numnber
	UDP_BUFFER           = 4096  //8192  //2048//socket receive buffer //2048时，最大容量20M byte
	RAW_BUFFER           = 12000 //1514  // rawSocket receive buffer//支持大包接收
	CONN_POOL            = 100   // conn pool cap
)
const moduleTag rlogger.ModuleTag = "upf"

// rawsocket
const (
	RAW_CHAN_CAP = 10000 // rawsocket receive channel buffer

)

const (
	UpfEtherLen   = 14
	UpfIPv4MinLen = 20
	UpfIPv6MinLen = 40
	UpfUDPLen     = 8
	UpfGtpLen     = 20
	UpfGtp16Len   = 16
	UpfGtpAddLen  = 12 // GTP头message len添加长度
	UpfGtp8AddLen = 8
)

// N3发包分片专用
const (
	BigPacketLenth    = 1466
	FragmentValue     = 1434
	EthIplength       = 34
	Gtp1FragmentValue = 1478
	Gtp2FragmentValue = 1482
)

const LocalExchangeGw = "0.0.0.0"

type MsgCxt struct {
	Msgbuf []byte
	Msgcxt *pdrcontext.DataFlowContext
}

type Ipv4Addr struct {
	Ipv4 net.IP
	Port int
}

type Ipv6Addr struct {
	Ipv6 net.IP
	Port int
}

// N3 udp server
type Server struct {
	MsgListChan [DPE_GOROUTINE_NUMBER]chan MsgCxt // receive msg list
	Ipv4Addr                                      //N3 upf ip
	Ipv6Addr                                      //N3 upf ipv6
	UpfConf     configure.UpfConfig
	DnGwIp      [4]byte
	// Performance improvement, 方案1内存池
	sp sync.Pool

	ServiceIP net.IP
}

// ReceiveMsg Send the received message to the ULD channel
func (s *Server) ReceiveMsg(msg []byte) bool {
	//rlogger.FuncEntry(moduleTag, nil)
	// todo: N3口增加传递上下文,解码后赋值
	msgCxt := MsgCxt{Msgbuf: msg,
		Msgcxt: &pdrcontext.DataFlowContext{},
	}
	DPENo := 0
	ipPacket, err := gtpv1u.GetRawIPPacket(msg)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to GetRawIPPacket,%s", err)
	}
	fiveTuple, err := utils.IpFiveTuple(ipPacket)
	if err != nil {
		DPENo = 0
	} else {
		// IP + port distribute
		DPENo = IpportdistributeNo(fiveTuple.SrcIp, fiveTuple.SrcPort)
	}
	// todo test
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "n3 send to dpe no(%d),%s+%d",
		DPENo, fiveTuple.SrcIp, fiveTuple.SrcPort)
	msgCxt.Msgcxt.UEIP = fiveTuple.SrcIp
	msgCxt.Msgcxt.UEPort = fiveTuple.SrcPort
	select {
	case s.MsgListChan[DPENo] <- msgCxt:
		return true
	default:
		return false //队列已满，消息丢弃

	}
	//fmt.Printf("chan: %s",<-s.MsgListChan)
}

var N3CountReceivePacket uint64
var N3CountSendPacket uint64

//var N3CountReceivePacket2 uint64

var N6CountReceivePacket uint64
var N6CountSendPacket uint64

func IpportdistributeNo(ip net.IP, port int) int {
	//rlogger.FuncEntry(moduleTag, nil)
	tmp := uint64(binary.BigEndian.Uint32(ip.To4()))
	number := (tmp + uint64(port)) % DPE_GOROUTINE_NUMBER
	return int(number)
}

// todo test config
var Dnn string = "cmnet"
var DnnIP string = "192.168.3.200"
var N3Ip string = "192.168.3.22"
var N4Ip string = "192.168.3.180"

type DnnGwIpMapKV struct {
	DnnName string
	GwIp    string
}

var SequenceNumber int32
