package n4udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
	flowT "github.com/intel-go/nff-go/types"
	xerrors "github.com/pkg/errors"
	"lite5gc/cmn/message/pfcp"
	"lite5gc/cmn/message/pfcp/pfcpudp"
	"lite5gc/cmn/message/pfcp/v1"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/am"
	"lite5gc/upf/context/gnbcontext"
	"lite5gc/upf/context/ipport"
	"lite5gc/upf/context/n4context"
	"lite5gc/upf/context/n4gtpcontext"
	"lite5gc/upf/cp/n4layer"
	"lite5gc/upf/defs"
	"lite5gc/upf/service/upfam"
	"net"
	"time"
)

// udp server
// server
// var UdpAddr = net.UDPAddr{IP: net.ParseIP(pfcpudp.PfcpDefaultIp), Port: 2152}
// var GtpServer = pfcpudp.NewUdpServer(&UdpAddr)
var Server = pfcpudp.PfcpServer
var GtpServer = pfcpudp.GtpServer

var ListenerN4PFCP *net.UDPConn
var ListenerN4GTP *net.UDPConn

func StartPfcpUdpListen(Cxt *types.AppContext, s *pfcpudp.Server) error {
	//defer func() {
	//	if err:=recover(); err!= nil {
	//		//pfcp 开启失败，产生告警
	//		alarmDetails:=upfam.UPFAlarmDetails{}
	//		alarmDetails.AlarmID=am.UPFN4UDPServer
	//		alarmDetails.Reason=fmt.Sprintf("UPF N4 udp server start error:%v",err)
	//		alarmDetails.Suggestion="check N4 configure"
	//		upfam.UPFAlarmReport(alarmDetails)//N4 UDP 开启失败告警
	//		panic(err)
	//	}
	//}()
	rlogger.FuncEntry(moduleTag, nil)
	listener, err := net.ListenUDP(
		"udp", s.LocalAddr)
	if err != nil {
		alarmDetails := upfam.UPFAlarmDetails{}
		alarmDetails.AlarmID = am.UPFN4UDPServer
		alarmDetails.Reason = fmt.Sprintf("UPF N4 udp server start error:%v", err)
		alarmDetails.Suggestion = "check N4 configure"
		upfam.UPFAlarmReport(alarmDetails) //N4 UDP 开启失败告警
		panic(fmt.Errorf("failed to Start Pfcp Udp Listen %s", err))
	}
	fmt.Printf("Cxt.ConfPath==\"%s\"\n", Cxt.ConfPath)
	if Cxt.ConfPath == "PFCP" {
		ListenerN4PFCP = listener
	} else {
		ListenerN4GTP = listener
	}

	fmt.Printf("Local: <%s> \n", listener.LocalAddr().String())
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "Local: <%s> \n", listener.LocalAddr().String())
	defer listener.Close()

	// 处理消息
	s.UdpConn = listener
	for i := 0; i < pfcpudp.HandleMsgGoroutineNumber; i++ {
		//upfCxt.Wg.Add(1)
		fmt.Printf("Start Pfcp handle(%v) \n", i)
		go handleRequestMsg(Cxt, s)
	}

	// performance improvement
	// 当前使用方式 2 ，静态申请
	for {
		select {
		case <-Cxt.Ctx.Done(): //接收消息的goroutine
			return fmt.Errorf("received a cancel singal")
		default:
		}
		var data [pfcpudp.UdpBuffer]byte

		n, remoteAddr, err := listener.ReadFromUDP(data[:])
		if err != nil {
			//fmt.Printf("error during read: %s", err)
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to read from udp")
			//if err == syscall.EINVAL {
			//	return err
			//}
			continue
		}
		//fmt.Printf("receive msg: <%#x>,from %s,to %s\n", data[:n], remoteAddr.String(), listener.LocalAddr().String())
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"receive msg: <%#x> ,from %s,to %s", data[:n], remoteAddr.String(), listener.LocalAddr().String())
		//receive msg: <hello> ,from 127.0.0.1:56191,to [::]:8805
		msgCxt := pfcpudp.MsgCxt{Msgbuf: data[:n],
			RemoteAdd: remoteAddr,
		}
		recvRet := s.ReceiveMsg(msgCxt)
		if recvRet != true {
			//fmt.Printf("The buffer is full, discarding the message\n")
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "The buffer is full, discarding the message")
		}

	}
	return nil

}

var IEerr = errors.New("IE incorrect")

// go,处理收的消息，并发送响应消息
func handleRequestMsg(Cxt *types.AppContext, s *pfcpudp.Server) error {
	rlogger.FuncEntry(moduleTag, nil)
	for {

		select {
		case msgCxt := <-s.RevMsgListChan:
			//fmt.Printf("receive msg:<%#x>,\nfrom %s,to %s \n", msgCxt.Msgbuf, s.UdpConn.LocalAddr().String(), msgCxt.RemoteAdd.String())
			//fmt.Printf("receive msg:<%#x>,\nfrom %s,to %s \n", msgCxt.Msgbuf, s.UdpConn.LocalAddr().String(), msgCxt.RemoteAdd.String())
			rlogger.Trace(moduleTag, rlogger.INFO, nil,
				"receive msg:<%#x>,\n  from %s,to %s \n", msgCxt.Msgbuf, msgCxt.RemoteAdd.String(), s.UdpConn.LocalAddr().String())
			//pfcp decode，result msg object

			// 处理N4口的GTP消息
			if s.LocalAddr.Port == 2152 {
				handleN4GTPMsg(msgCxt.Msgbuf)
				continue
			}
			//todo pfcp decode
			msg := pfcpv1.Message{}
			res := &pfcpv1.Message{}
			err1, err := pfcpv1.ProtectUnmarshalRun(msg.Unmarshal, msgCxt.Msgbuf)
			if err1 != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil,
					"receive msg:<%#x>,\n  unmarshal panic:%+v \n", msgCxt.Msgbuf, err1)
				continue
			}
			//err = msg.Unmarshal(msgCxt.Msgbuf)
			if err != nil && xerrors.Cause(err).Error() == IEerr.Error() {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil,
					"receive msg:<%#x>,\n  unmarshal error:%+v \n", msgCxt.Msgbuf, err)
				err = ProtectDirectResponsePRun(DirectResponse, msg, res, msgCxt.RemoteAdd, s)
				if err != nil {
					rlogger.Trace(moduleTag, rlogger.ERROR, nil,
						"response msg (with IE incorrect) send error:%+v \n", err)
				}
				//DirectResponse(msg,res,msgCxt.RemoteAdd,s)
				continue
			}
			//if err != nil && err.Error() == IEerr.Error() {
			//	err = ProtectDirectResponsePRun(DirectResponse, msg, res, msgCxt.RemoteAdd, s)
			//	if err != nil {
			//		continue
			//	}
			//	//DirectResponse(msg,res,msgCxt.RemoteAdd,s)
			//	continue
			//}
			//if err != nil {
			//	rlogger.Trace(moduleTag, rlogger.ERROR, nil,
			//		"receive msg:<%#x>,\n  unmarshal error:%s \n", msgCxt.Msgbuf, err)
			//	continue
			//}

			rlogger.Trace(moduleTag, rlogger.INFO, nil, "receive msg:(%s)", &msg)

			peerIp := msgCxt.RemoteAdd
			err = Dispatch(peerIp, msg, res)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil,
					"receive msg:(%s),\n  Dispatch error:%+v \n",
					msg.String(), err)
				continue
			}
			// response message end processing
			if res.Header.MessageType == 0 {
				rlogger.Trace(moduleTag, rlogger.INFO, nil,
					"Message type error,send msg:(%s)", res.String())
				continue
			}
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "send msg:(%s)", res.String())
			// todo pfcp encode
			err1, data, err := pfcpv1.ProtectMarshalRun(res.Marshal)
			if err1 != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil,
					"response msg marshal panic:%+v \n", err1)
				continue
			}
			//data, err := res.Marshal()
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to marshal,error:%+v", err)
				continue
			}
			err1, err = pfcpv1.ProtectWriteToUDPRun(s.UdpConn.WriteToUDP, data, msgCxt.RemoteAdd)
			if err1 != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil,
					"response msg marshal panic:%+v \n", err1)
				continue
			}
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to send,error:%+v", err)
				continue
			}
			//s.UdpConn.WriteToUDP(data, msgCxt.RemoteAdd)
			//fmt.Printf("send msg:<%#x>,from %s,to %s \n", data, s.UdpConn.LocalAddr().String(), msgCxt.RemoteAdd.String())
			rlogger.Trace(moduleTag, rlogger.INFO, nil,
				"send msg:<%#x>,from %s,to %s \n", data, s.UdpConn.LocalAddr().String(), msgCxt.RemoteAdd.String())
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "success to send msg")
		case <-Cxt.Ctx.Done(): //处理n4消息的goroutine
			return fmt.Errorf("received a cancel singal")
		}
	}
}

// handleN4GTPMsg
func handleN4GTPMsg(Msgbuf []byte) {
	var teid uint32
	teid = binary.BigEndian.Uint32(Msgbuf[4:8])
	seid, err := n4gtpcontext.Get(teid)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
			"GetSeidFromTeid teid:%v,err:%s", teid, err)
		return
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.DEBUG, nil,
		"GetSeidFromTeid teid:%#x,seid:%v", teid, seid)

	n4ctx, err := n4context.GetN4Context(n4context.N4SessionIDKey(seid.Seid))
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
			"GetSeidFromTeid seid:%v,err:%v", seid, err)
		return
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.DEBUG, nil,
		"testdst seid:%v,n4ctx Gnb %s:teid %v", seid, n4ctx.GnbIp, n4ctx.GnbTeid)
	//todo 获取N3口信息并发送
	N4SMFTeid := n4ctx.GnbTeid

	rlogger.Trace(types.ModuleUpfN4Node, rlogger.DEBUG, nil,
		"n4ctx.GnbTeid:%+v, n4ctx.GnbIp:%+v, n4ctx.N4SMFGTPIp:%+v, n4ctx.N4SMFTeid:%+v", n4ctx.GnbTeid, n4ctx.GnbIp, n4ctx.N4SMFGTPIp, n4ctx.N4SMFTeid)

	for i := 7; i > 3; i-- {
		Msgbuf[i] = byte(N4SMFTeid % 256)
		N4SMFTeid /= 256
	}

	retVal := true

	if n4ctx.GnbInfo.IpType == gnbcontext.Type_IPv6_address {
		currentPacket, err := packet.NewArpBufPacket()
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		ok := packet.InitEmptyIPv6UDPPacket(currentPacket, uint(len(Msgbuf)))
		if !ok {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to InitEmptyIPv4UDPPacket")
			return
		}

		currentPacket.ParseL3()

		ipv6 := currentPacket.GetIPv6NoCheck() //(*packet.IPv6Hdr)(currentPacket.L3)
		ipv6.SrcAddr = flowT.SliceToIPv6(net.ParseIP(configure.UpfConf.N3.Ipv6).To16())
		ipv6.DstAddr = flowT.SliceToIPv6(n4ctx.GnbIp)
		//非固定头填充
		currentPacket.PacketBytesChange(14+40+8, Msgbuf)
		Ipport := ipport.IpPorts[ipport.N3Outport]
		// Fill L2
		currentPacket.Ether.EtherType = flowT.SwapIPV6Number
		currentPacket.Ether.SAddr = Ipport.MacAddress
		if Ipport.StaticARP {
			currentPacket.Ether.DAddr = Ipport.DstMacAddress
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv6 Static currentPacket.Ether.DAddr", currentPacket.Ether.DAddr)
		} else {
			// Find l2 addresses for new destionation IP in ARP cache
			// Next hop local exchange, targetIP is gnb ip
			targetIP := flowT.SliceToIPv6(n4ctx.GnbIp) //ipv6.DstAddr
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv6 targetIP %s", targetIP)

			targetMAC, found := Ipport.NeighCache.LookupMACForIPv6(targetIP)
			if !found {
				// fmt.Println("Not found MAC address for IP", targetIP.String())
				Ipport.NeighCache.SendNeighborSolicitationForIPv6(targetIP, ipv6.SrcAddr, 0)
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "ipv6 targetIP %s, ipv6 SrcAddr %s,", targetIP, ipv6.SrcAddr)

				retVal = false

			}
			currentPacket.Ether.DAddr = targetMAC
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv6 currentPacket.Ether.DAddr %s", currentPacket.Ether.DAddr)
		}
		// fill ip
		// Fill up l3
		ipv6.VtcFlow = 0x60
		ipv6.Proto = flowT.UDPNumber
		ipv6.HopLimits = 255

		length := currentPacket.GetPacketLen()
		ipv6.PayloadLen = packet.SwapBytesUint16(uint16(length - defs.UpfEtherLen - defs.UpfIPv6MinLen))

		// fill udp
		// Fill up L4
		currentPacket.ParseL4ForIPv6()
		udp := currentPacket.GetUDPForIPv6()
		udp.SrcPort = packet.SwapUDPPortGTPU
		udp.DstPort = packet.SwapUDPPortGTPU
		udp.DgramLen = packet.SwapBytesUint16(uint16(length - defs.UpfEtherLen - defs.UpfIPv6MinLen))
		currentPacket.ParseL7(flowT.UDPNumber)
		// 清除checksums，由网卡硬件计算
		udp.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv6UDPCksum(ipv6, udp))
		currentPacket.SetTXIPv6UDPOLFlags(defs.UpfEtherLen, defs.UpfIPv6MinLen)

		if !retVal {
			// 没有find, 将报文先保存起来，如果缓存中的报文数量超过200个，将旧的释放掉。第一次不加锁是为了性能考虑
			rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Start storing  arp packet to GArpBuffers: %v", currentPacket.Ether)
			if packet.GArpBuffers.Len() > 200 {
				packet.GArpMutex.Lock()
				if packet.GArpBuffers.Len() > 200 {
					bufferHead := packet.GArpBuffers.Front()
					packet.GArpBuffers.Remove(bufferHead)
					packet.GArpMutex.Unlock()
					oldPacket := bufferHead.Value.(*packet.Packet)
					oldPacket.FreePacket()
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Free an oldPacket in GArpBuffer to store newPacket ")
				} else {
					packet.GArpMutex.Unlock()
				}
			}
			//rlogger.Trace(moduleTag, rlogger.DEBUG, N3Cxt.Msgcxt.UEIP, "[2] save packet.Ether %s", currentPacket.Ether)
			srcbuf := currentPacket.GetRawPacketBytes()
			// 从arp buf pool里申请一个mbuf内存缓存起来
			arpPacket, _ := packet.NewArpBufPacket()
			if nil != arpPacket {
				arpbuf := (*[2 << 10]byte)(arpPacket.StartAtOffset(0))
				copy(arpbuf[0:], srcbuf)
				srcbuf[12] = 255
				arpPacket.PacketSetDataLen(uint(len(srcbuf)))
				arpPacket.ParseL3()
				arpPacket.SetTXIPv6UDPOLFlags(defs.UpfEtherLen, defs.UpfIPv6MinLen)

				packet.GArpMutex.Lock()
				packet.GArpBuffers.PushBack(arpPacket)
				packet.GArpMutex.Unlock()
				rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Storing  arp packet to GArpBuffers success, currentPacket.Ether: %+v", currentPacket.Ether)
			}
			rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Packet abort:get raw packet bytes from  ARP buf failed: %+v", currentPacket.Ether)
			return
		}
		currentPacket.SendPacket(uint16(configure.UpfConf.N3.PortId))
		rlogger.Trace(moduleTag, rlogger.DEBUG, nil,
			"send RA msg:<%#x>,\n", Msgbuf)
		return
	}
	currentPacket, err := packet.NewArpBufPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	ok := packet.InitEmptyIPv4UDPPacket(currentPacket, uint(len(Msgbuf)))
	if !ok {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to InitEmptyIPv4UDPPacket")
		return
	}

	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4NoCheck() //(*packet.IPv4Hdr)(currentPacket.L3)
	ipv4.SrcAddr = flowT.SliceToIPv4(net.ParseIP(configure.UpfConf.N3.Ipv4).To4())
	ipv4.DstAddr = flowT.SliceToIPv4(n4ctx.GnbIp)
	//非固定头填充
	currentPacket.PacketBytesChange(14+20+8, Msgbuf)
	Ipport := ipport.IpPorts[ipport.N3Outport]
	// Fill L2
	currentPacket.Ether.EtherType = flowT.SwapIPV4Number
	currentPacket.Ether.SAddr = Ipport.MacAddress
	if Ipport.StaticARP {
		currentPacket.Ether.DAddr = Ipport.DstMacAddress
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 Static currentPacket.Ether.DAddr", currentPacket.Ether.DAddr)
	} else {
		// Find l2 addresses for new destionation IP in ARP cache
		// Next hop local exchange, targetIP is gnb ip
		targetIP := flowT.SliceToIPv4(n4ctx.GnbIp) //ipv4.DstAddr
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 targetIP %s", targetIP)
		// Next hop gateway exchange, targetIP is gateway ip
		gwIp := configure.UpfConf.N3.Gateway
		if gwIp != defs.LocalExchangeGw {
			if net.ParseIP(gwIp).To4() == nil {
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "gnb gateway ip is nil")
				return
			}
			targetIP = flowT.SliceToIPv4(net.ParseIP(gwIp).To4())
		}

		targetMAC, found := Ipport.NeighCache.LookupMACForIPv4(targetIP)
		if !found {
			// fmt.Println("Not found MAC address for IP", targetIP.String())
			Ipport.NeighCache.SendARPRequestForIPv4(targetIP, ipv4.SrcAddr, 0)
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "ipv4 targetIP %s, ipv4 SrcAddr %s,", targetIP, ipv4.SrcAddr)

			retVal = false

		}
		currentPacket.Ether.DAddr = targetMAC
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 currentPacket.Ether.DAddr %s", currentPacket.Ether.DAddr)
	}

	// 固定头填充
	// Fill new IPv4 header with addresses according to context
	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = 0xe803
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	length := currentPacket.GetPacketLen()
	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - flowT.EtherLen))
	ipv4.NextProtoID = flowT.UDPNumber
	ipv4.HdrChecksum = 0

	// Fill up L4
	currentPacket.ParseL4ForIPv4()
	udp := currentPacket.GetUDPForIPv4()
	udp.SrcPort = packet.SwapUDPPortGTPU
	udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = packet.SwapBytesUint16(uint16(length - flowT.EtherLen - flowT.IPv4MinLen))
	currentPacket.ParseL7(flowT.UDPNumber)
	// Calculate checksums
	ipv4.HdrChecksum = 0
	//todo 虚拟网卡不支持自计算
	//ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	//udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, currentPacket.Data))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4UDPCksum(ipv4, udp))
	currentPacket.SetTXIPv4UDPOLFlags(flowT.EtherLen, flowT.IPv4MinLen)

	if !retVal {
		// 将报文先保存起来
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
		srcbuf := currentPacket.GetRawPacketBytes()
		// 从arp buf pool里申请一个mbuf内存缓存起来
		arpPacket, _ := packet.NewArpBufPacket()
		if nil != arpPacket {
			arpbuf := (*[2 << 10]byte)(arpPacket.StartAtOffset(0))
			copy(arpbuf[0:], srcbuf)
			arpPacket.PacketSetDataLen(uint(len(srcbuf)))
			arpPacket.ParseL3()
			arpPacket.SetTXIPv4UDPOLFlags(flowT.EtherLen, flowT.IPv4MinLen)

			packet.GArpMutex.Lock()
			packet.GArpBuffers.PushBack(arpPacket)
			packet.GArpMutex.Unlock()
		}

		return
	}
	time.Sleep(time.Millisecond)
	currentPacket.SendPacket(uint16(configure.UpfConf.N3.PortId))
	rlogger.Trace(moduleTag, rlogger.DEBUG, nil,
		"send RA msg:<%#x>,\n", Msgbuf)
	return
}
func ProtectDirectResponsePRun(entry func(pfcpv1.Message, *pfcpv1.Message, *net.UDPAddr, *pfcpudp.Server), msg pfcpv1.Message, res *pfcpv1.Message, addr *net.UDPAddr, s *pfcpudp.Server) (err1 error) {
	defer func(err2 *error) {
		if err := recover(); err != nil {
			rlogger.Trace("n4udp", rlogger.ERROR, nil,
				"DirectResponse appear panic : %+v \n", err)
			*err2 = errors.New("DirectResponse panic")
		}
	}(&err1)
	entry(msg, res, addr, s)
	return err1
}
func DirectResponse(msg pfcpv1.Message, res *pfcpv1.Message, addr *net.UDPAddr, s *pfcpudp.Server) {
	rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "response not normal")
	switch msg.Header.MessageType {
	case pfcp.PFCP_Association_Setup_Request:
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,
			"Unmarshal  IEPFCPAssociationSetupRequest IE is error\n")

		response := &pfcp.PFCPAssociationSetupResponse{
			PfcpHeader: pfcp.PfcpHeaderforNode{
				Version:        pfcp.Version,
				MessageType:    pfcp.PFCP_Association_Setup_Response,
				Length:         0, // todo 编码后填充
				SequenceNumber: 1},
		}
		response.IE = &pfcp.IEPFCPAssociationSetupResponse{}
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 5,
			},
			NodeIDType:  0,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4(), //[]byte{10, 202, 94, 1},
		}
		response.IE.Cause = &pfcp.IECause{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeCause,
				Length: 1,
			},
			CauseValue: pfcp.Cause_Mandatory_IE_incorrect,
		}

		response.IE.RecoveryTimeStamp = &pfcp.IERecoveryTimeStamp{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeRecoveryTimeStamp,
				Length: 4,
			},
			RecoveryTimeStamp: time.Unix(time.Now().Unix(), 0), //time.Unix(1556588833, 0),
		}
		res.Header.Version = response.PfcpHeader.Version
		res.Header.MessageType = response.PfcpHeader.MessageType
		res.Header.Length = response.PfcpHeader.Length
		res.Header.SequenceNumber = response.PfcpHeader.SequenceNumber
		res.Body = response
	case pfcp.PFCP_Association_Update_Request:
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,
			"Unmarshal  IEPFCP_Association_Update_Request IE is error\n")
		response := &pfcp.PFCPAssociationUpdateResponse{
			PfcpHeader: pfcp.PfcpHeaderforNode{
				Version:        pfcp.Version,
				MessageType:    pfcp.PFCP_Association_Update_Response,
				Length:         0, // todo 编码后填充
				SequenceNumber: 1},
		}
		response.IE = &pfcp.IEPFCPAssociationUpdateResponse{}
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 5,
			},
			NodeIDType:  0,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4(), //[]byte{10, 202, 94, 1},
		}
		response.IE.Cause = &pfcp.IECause{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeCause,
				Length: 1,
			},
			CauseValue: pfcp.Cause_Mandatory_IE_incorrect,
		}
		res.Header.Version = response.PfcpHeader.Version
		res.Header.MessageType = response.PfcpHeader.MessageType
		res.Header.Length = response.PfcpHeader.Length
		res.Header.SequenceNumber = response.PfcpHeader.SequenceNumber
		res.Body = response
	case pfcp.PFCP_Association_Release_Request:
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,
			"Unmarshal  IEPFCP_Association_Release_Request IE is error\n")
		response := &pfcp.PFCPAssociationReleaseResponse{
			PfcpHeader: pfcp.PfcpHeaderforNode{
				Version:        pfcp.Version,
				MessageType:    pfcp.PFCP_Association_Release_Response,
				Length:         0, // todo 编码后填充
				SequenceNumber: 1},
		}
		response.IE = &pfcp.IEPFCPAssociationReleaseResponse{}
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 5,
			},
			NodeIDType:  0,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4(), //[]byte{10, 202, 94, 1},
		}
		response.IE.Cause = &pfcp.IECause{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeCause,
				Length: 1,
			},
			CauseValue: pfcp.Cause_Mandatory_IE_incorrect,
		}
		res.Header.Version = response.PfcpHeader.Version
		res.Header.MessageType = response.PfcpHeader.MessageType
		res.Header.Length = response.PfcpHeader.Length
		res.Header.SequenceNumber = response.PfcpHeader.SequenceNumber
		res.Body = response
	case pfcp.PFCP_Session_Establishment_Request:
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,
			"Unmarshal  IEPFCP_Session_Establishment_Request IE is error\n")
		var n4 n4layer.N4Msg
		request, _ := msg.Body.(pfcp.SessionEstablishmentRequest)

		//解码消息头填充处理消息头
		request.PfcpHeader.Version = msg.Header.Version
		request.PfcpHeader.MPFlag = msg.Header.MPFlag
		request.PfcpHeader.SFlag = msg.Header.SFlag

		request.PfcpHeader.MessageType = msg.Header.MessageType
		request.PfcpHeader.Length = msg.Header.Length
		request.PfcpHeader.SEID = msg.Header.SEID
		request.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber
		request.PfcpHeader.MessagePriority = msg.Header.MessagePriority

		response := &pfcp.SessionEstablishmentResponse{}

		n4.SessionEstablishmentRequest(request, response)

		pfcpHeader := pfcp.PfcpHeader{}
		pfcpHeader.Version = response.PfcpHeader.Version
		pfcpHeader.MPFlag = response.PfcpHeader.MPFlag
		pfcpHeader.SFlag = response.PfcpHeader.SFlag

		pfcpHeader.MessageType = response.PfcpHeader.MessageType
		pfcpHeader.Length = response.PfcpHeader.Length
		pfcpHeader.SEID = response.PfcpHeader.SEID
		pfcpHeader.SequenceNumber = response.PfcpHeader.SequenceNumber
		pfcpHeader.MessagePriority = response.PfcpHeader.MessagePriority
		response.IE.Cause.CauseValue = pfcp.Cause_Mandatory_IE_incorrect
		res.Header = pfcpHeader
		res.Body = response

	}

	data, err := res.Marshal()
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to marshale,error:%s", err)
		return
	}
	s.UdpConn.WriteToUDP(data, addr)
	//fmt.Printf("send msg:<%#x>,from %s,to %s \n", data, s.UdpConn.LocalAddr().String(), msgCxt.RemoteAdd.String())
	rlogger.Trace(moduleTag, rlogger.INFO, nil,
		"send msg:<%#x>,from %s,to %s \n", data, s.UdpConn.LocalAddr().String(), addr.String())
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "success to send msg")
}

// client

func SendUdpMsg(s *pfcpudp.Server) error {
	rlogger.FuncEntry(moduleTag, nil)
	//对端地址

	//srcAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	//dstAddr := &net.UDPAddr{IP: ip, Port: port}

	conn, err := net.DialUDP("udp", s.LocalAddr, s.PeerAddr)
	if err != nil {
		fmt.Println(err)
		//rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to get UPD send connection!")
		return err
	}
	defer conn.Close()
	fmt.Println(conn)
	for {
		select {
		case UDPMsg := <-s.SendMsgListChan:
			n, err := conn.Write(UDPMsg.Msgbuf)
			if err != nil {
				fmt.Printf("failed to write: %v", err)
			}
			//rlogger.Trace(moduleTag, rlogger.INFO, nil,  "<%s>--><%s>: %#x\n", conn.LocalAddr(), conn.RemoteAddr(), UDPMsg[:n])
			fmt.Printf("SendN4UdpMsg to Peer : <%s>--><%s>: %s\n", conn.LocalAddr(), conn.RemoteAddr(), UDPMsg.Msgbuf[:n])
		}
	}

	return nil
}

var N4AllCancelFunc func()
var N4UDPCancelFunc func()
var N4GTPCancelFunc func()
var ContextForN4 context.Context

func StartN4Server(Cxt *types.AppContext) error {
	rlogger.FuncEntry(moduleTag, nil)
	n4layer.UpfN4Layer.UpfIp = configure.UpfConf.N4.Local.Ipv4
	n4layer.UpfN4Layer.N3Ip = configure.UpfConf.N3.Ipv4
	n4layer.UpfN4Layer.N3Ipv6 = configure.UpfConf.N3.Ipv6
	// 开启N4监听
	//Cxt.Wg.Add(1)
	//go StartN4Listen(Cxt)
	Server.LocalAddr.IP = net.ParseIP(configure.UpfConf.N4.Local.Ipv4)
	Server.LocalAddr.Port = configure.UpfConf.N4.Local.Port
	GtpServer.LocalAddr.IP = net.ParseIP(configure.UpfConf.N4.Local.Ipv4)
	GtpServer.LocalAddr.Port = configure.UpfConf.N4Gtp.Local.Port
	cxt, n4AllCancel := context.WithCancel(Cxt.Ctx)
	cxtUDP, n4UDPCancel := context.WithCancel(cxt)
	cxtGTP, n4GTPCancel := context.WithCancel(cxt)
	N4AllCancelFunc = n4AllCancel
	N4UDPCancelFunc = n4UDPCancel
	N4GTPCancelFunc = n4GTPCancel
	//存储到全局变量中去：可以在后续的过程中取消：
	ctxForUDP := types.AppContext{
		Ctx:      cxtUDP,
		ConfPath: "PFCP",
	}
	ctxForGTP := types.AppContext{
		Ctx:      cxtGTP,
		ConfPath: "GTP",
	}
	ContextForN4 = cxt
	//保存上下文到全局变量
	go StartPfcpUdpListen(&ctxForUDP, Server)
	go StartPfcpUdpListen(&ctxForGTP, GtpServer)
	return nil
}

func N4PFCPCancel() error {
	if ListenerN4PFCP == nil {
		fmt.Println("ListenerN4PFCP is nil")
		return nil //没有开启，可以直接开启
	}
	if N4UDPCancelFunc != nil {
		ListenerN4PFCP.Close()
		N4UDPCancelFunc()
		return nil
	} else {
		return fmt.Errorf("cancel function is nil")
	}
}
func N4GTPCancel() error {
	if ListenerN4GTP == nil {
		fmt.Println("ListenerN4PFCP is nil")
		return nil //没有开启，可以直接开启
	}
	if N4GTPCancelFunc != nil {
		ListenerN4GTP.Close()
		N4GTPCancelFunc()
		return nil
	} else {
		return fmt.Errorf("cancel function is nil")
	}
}

func RestartN4PFCP() error {
	//关闭现有的n4服务
	err := N4PFCPCancel()
	if err != nil {
		return err
	}
	//todo 修改网卡配置，如修改ip地址
	//n4ctx.Wg.Wait()
	time.Sleep(1 * time.Second)
	//重启n4服务
	n4layer.UpfN4Layer.UpfIp = configure.UpfConf.N4.Local.Ipv4
	n4layer.UpfN4Layer.N3Ip = configure.UpfConf.N3.Ipv4
	n4layer.UpfN4Layer.N3Ipv6 = configure.UpfConf.N3.Ipv6
	// 开启N4监听
	Server.LocalAddr.IP = net.ParseIP(configure.UpfConf.N4.Local.Ipv4)
	Server.LocalAddr.Port = configure.UpfConf.N4.Local.Port
	cxtUDP, n4UDPCancel := context.WithCancel(ContextForN4)
	N4UDPCancelFunc = n4UDPCancel
	//存储到全局变量中去：可以在后续的过程中取消：
	ctxForUDP := types.AppContext{
		Ctx:      cxtUDP,
		ConfPath: "PFCP",
	}
	go StartPfcpUdpListen(&ctxForUDP, Server)
	return nil
}

func RestartN4GTP() error {
	//关闭现有的n4服务
	err := N4GTPCancel()
	if err != nil {
		return err
	}
	//todo 修改网卡配置，如修改ip地址
	time.Sleep(1 * time.Second)
	n4layer.UpfN4Layer.UpfIp = configure.UpfConf.N4.Local.Ipv4
	n4layer.UpfN4Layer.N3Ip = configure.UpfConf.N3.Ipv4
	n4layer.UpfN4Layer.N3Ipv6 = configure.UpfConf.N3.Ipv6
	// 开启N4监听
	//Cxt.Wg.Add(1)
	//go StartN4Listen(Cxt)
	GtpServer.LocalAddr.IP = net.ParseIP(configure.UpfConf.N4Gtp.Local.Ipv4)
	GtpServer.LocalAddr.Port = configure.UpfConf.N4Gtp.Local.Port
	cxtGTP, n4GTPCancel := context.WithCancel(ContextForN4)
	N4GTPCancelFunc = n4GTPCancel
	//存储到全局变量中去：可以在后续的过程中取消：
	ctxForGTP := types.AppContext{
		Ctx:      cxtGTP,
		ConfPath: "GTP",
	}
	//保存上下文到全局变量
	go StartPfcpUdpListen(&ctxForGTP, GtpServer)
	return nil
}
