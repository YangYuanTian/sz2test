/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/3/31 10:28
* Description:
 */
package gtpsignalling

import (
	"context"
	"errors"
	"fmt"
	"github.com/intel-go/nff-go/packet"
	flowT "github.com/intel-go/nff-go/types"
	"lite5gc/cmn/message/gtpv1u"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/am"
	"lite5gc/upf/adapter"
	"lite5gc/upf/context/gnbcontext"
	"lite5gc/upf/context/ipport"
	"lite5gc/upf/context/pfcpgnbcontext"
	"lite5gc/upf/cp/n4node"
	"lite5gc/upf/defs"
	"lite5gc/upf/metrics"
	"lite5gc/upf/service/gtpsignalling/signaldef"
	"lite5gc/upf/service/upfam"
	"net"
	"time"
)

//------------------------------------------------------------------------------
//N3路径故障上报
//SMF与UPF之间建立PFCP节点，保存于PFCP节点表
//UPF创建会话，保存N4会话信息，保存节点信息，从会话信息中抽取GNB信息，保存GNB信息（gnb信息表）；保存gnb与pfcp节点关系表
//去重，保存gnb与pfcp节点关系表，key：gnb ip+pfcp ip；value：gnb info、pfcp node info
//故障上报，遍历gnb与pfcp节点关系表，gnb ip相同时，得到上报的pfcp node info，发送上报
//------------------------------------------------------------------------------

// 开启echo功能
// StartEchoServer
func StartEchoServer(upfCtxt *types.AppContext) error {
	rlogger.FuncEntry(types.ModuleUpfServiceEcho, nil)
	// create a receive message server
	EchoServer := signaldef.EchoServer
	if EchoServer == nil {
		//panic("Failed to apply for memory")
		return errors.New("Failed to apply for memory")
	}

	// 处理Gnb Echo请求
	go StartGnbEchoHandle(upfCtxt, EchoServer)

	return nil
}

// StartGnbEchoHandle goroutine开启接收新增gnb处理
func StartGnbEchoHandle(upfCtxt *types.AppContext, server *signaldef.EchoHandle) {
	fmt.Printf("start gnb echo\n")
	rlogger.FuncEntry(types.ModuleUpfServiceEcho, nil)
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "gnb echo server routine start")
	upfCtxt.Wg.Add(1)
	defer upfCtxt.Wg.Done()

	for {
		select {
		case <-upfCtxt.Ctx.Done():
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "raw dpe Paging server routine exit")
			return

		case msg := <-server.RevGnbInfoChan:
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "start gnb echo,receive gnb info :%+v", *msg)
			// 启动 gnb echo
			err := EchoHandle(msg)
			if err != nil {
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "Failed to start echo sending :%+v", *msg)
			}
		}
	}
}

// 在每条路径上，回声请求的发送频率不得超过每60秒一次。
// 3次没有响应，判定为对端故障，关闭echo发送，从gnbTable中删除gnb地址，
// 然后，触发路径故障上报给smf
func EchoHandle(gnb *gnbcontext.GnbInfo) error {
	rlogger.FuncEntry(types.ModuleUpfServiceEcho, nil)

	// 发送echo 消息
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "gnb IP %s ", gnb.Ip.IP.String())
	//gnb IP地址为I-UPF(上行分类器)表明发送者为PAS-UPF，即不需要向gnb发送echo消息
	//if n4layer.UpfIUpf!=nil&&strings.Contains(gnb.Ip.IP.String(),n4layer.UpfIUpf.IPv4Addr.String()){
	//	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "UpfIUpf %s ",n4layer.UpfIUpf.IPv4Addr.String())
	//	return nil
	//}
	go EchoSetup(gnb)

	return nil
}

// 接收 Echo response
func EchoResponseHandle(n *gnbcontext.GnbInfo, msg *gtpv1u.EchoResponse) error {
	rlogger.FuncEntry(types.ModuleUpfServiceEcho, nil)
	// 关闭重传
	if n.NTimer.T1RetransCancel != nil {
		n.NTimer.T1RetransCancel()
	}
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "node:%s, echo response msg %+v", n.Ip.IP, msg)
	metrics.UpfmoduleSet.EchoResponse.Inc(1)
	return nil
}

func EchoSetup(gnb *gnbcontext.GnbInfo) {
	rlogger.FuncEntry(types.ModuleUpfServiceEcho, nil)
	//1、在节点创建后启动60s定时器
	t1 := time.NewTimer(gtpv1u.T1)

	cxt, cancel := context.WithCancel(context.Background())
	gnb.NTimer.T1Cancel = cancel // stop timer
	//reSetcxt, reset := context.WithCancel(context.Background())
	reSetcxt := make(chan struct{}, 1)
	reset := func() {
		reSetcxt <- struct{}{}
	}
	// reset timer
	gnb.NTimer.T1Reset = reset

	gnb.NTimer.T1 = t1

	for {
		select {
		case <-reSetcxt:
			//3、收到节点内的任何消息（除节点释放消息），重置定时器
			t1.Reset(gtpv1u.T1)
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "node:%s,reset echo", gnb.Ip.IP)
			//rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "node:%s,reset Heartbeat timer ", n.NodeID, t1)

		case <-cxt.Done(): // 关闭chan，不阻塞
			//4、释放节点后，关闭echo定时器
			t1.Stop()
			// 关闭关联go
			if gnb.NTimer.T1RetransCancel != nil {
				gnb.NTimer.T1RetransCancel()
			}
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "node:%s,stop echo", gnb.Ip.IP)
			// 清理gnb节点信息
			gnbcontext.DeleteGnb(gnb.Ip.IP.String())
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "gnb node release(%s)", gnb.Ip.IP)
			return
		case <-t1.C:
			//	发送echo消息,一个协程处理发送处理
			go sendEchoRequestMsg(gnb)
			t1.Reset(gtpv1u.T1)
		}
	}
}

func sendEchoRequestMsg(n *gnbcontext.GnbInfo) { // f 是非阻塞调用
	//rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//2、3s到发送heartbeat消息
	// 创建消息
	msgbuf, err := adapter.EchoRequestCreate(n)
	if err != nil {
		return
	}
	//todo 与基站重新建立联系，产生告警清除
	gnbReconnect, _ := upfam.GnbReconnect.Get(n.Ip.IP.String())
	if gnbReconnect {
		alarmDetails := upfam.UPFAlarmDetails{
			Substring:   n.Ip.IP.String(),
			AlarmID:     am.UPFGnbHeartBeat,
			Reason:      "alarm clear:echo timeout",
			PeerAddress: n.Ip.String(),
		}
		upfam.UPFAlarmClear(alarmDetails) //基站回送响应超时告警清除
		upfam.GnbReconnect.Add(n.Ip.IP.String(), false)
	}
	// 启动响应超时重传
	// 启动3次重传, 触发路径故障上报
	err = EchoTimeoutRetransmission(n, msgbuf)
	if err != nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "gtp echo msg Timeout retransmission err: %s", err)
	}
	//设置流程的当前状态

}
func SendEchoResponse(n *gnbcontext.GnbInfo, EchoRequestMsg *gtpv1u.EchoRequest) bool {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	N3EncodeMsg := &gtpv1u.EchoResponse{}

	//填充GTPv1U协议头部
	N3EncodeMsg.Version = gtpv1u.Protocol_version
	N3EncodeMsg.PT = gtpv1u.Protocol_Type
	N3EncodeMsg.SFlag = gtpv1u.Protocol_Present
	N3EncodeMsg.MessageType = gtpv1u.Msg_Type_Echo_Response
	N3EncodeMsg.TEID = 0

	N3EncodeMsg.SequenceNumber = EchoRequestMsg.SequenceNumber

	N3EncodeMsg.Length = uint16(6)

	N3EncodeMsg.IE.IsPresence = false
	N3EncodeMsg.IE.Recovery.Type = gtpv1u.IE_Type_Recovery
	// test 删除IP与UDP头
	//N3EncodeMsg.Gtpbody = N3EncodeMsg.Gtpbody[28:]
	data, err := N3EncodeMsg.EncodeMsg()
	if err != nil {
		//fmt.Println(err)
		//rlogger.Trace(moduleTag, types.ERROR, Msgcxt, "Failed to N6 message Eecode!")
		// N3DecodeMsg failed,discard message
		return false
	}
	//fmt.Println(len(Msgbuf))
	//fmt.Printf("Encode value: %#x\n", Msgbuf)
	//rlogger.Trace(moduleTag, types.DEBUG, Msgcxt, "Encode value: %#x\n", Msgbuf)
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "successfully to gtp echo response msg send")
	return sendEchoNffMsg(n, data)
}
func sendEchoNffMsg(n *gnbcontext.GnbInfo, body []byte) bool {
	retVal := true
	defer func() {
		if err := recover(); err != nil {
			retVal = false
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "send echo nff message error:", err)
		}
	}()
	// 加gtp包头
	//currentPacket.EncapsulateIPv4GTP()
	if n.IpType == gnbcontext.Type_IPv6_address {
		etherLen := uint(flowT.EtherLen)
		ipv6Len := uint(flowT.IPv6Len)
		UDPLen := uint(flowT.UDPLen)
		GTPMinLen := uint(flowT.GTPMinLen)
		GTPMinLen = 12
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil,
			"add gtp head,etherLen-ipv6MinLen-UDPLen-GTPMinLen", etherLen, ipv6Len, UDPLen, GTPMinLen)
		//length := currentPacket.GetPacketLen() - flowT.EtherLen
		// 创建 packet
		currentPacket, err := packet.NewPacket()
		if err != nil {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to NewPacket")
			return false
		}
		ok := packet.InitEmptyIPv6UDPPacket(currentPacket, uint(len(body)))
		if !ok {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to InitEmptyIPv4UDPPacket")
			return false
		}

		currentPacket.ParseL3()
		//非固定头填充
		currentPacket.PacketBytesChange(etherLen+ipv6Len+UDPLen, body)
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "change echo Message len=%d value: %#x", len(body), body)

		// 固定头填充
		// Fill new IPv4 header with addresses according to context
		ipv6 := currentPacket.GetIPv6NoCheck() //(*packet.IPv4Hdr)(currentPacket.L3)

		// 源IP，目的IP
		if len(ipport.IpPorts) <= int(ipport.N3Outport) {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil,
				"len of IpPorts %v", "N3Outport %v", len(ipport.IpPorts), ipport.N3Outport)
		}
		Ipport := ipport.IpPorts[ipport.N3Outport]
		srcAddr := Ipport.Subnet.IPv6.Addr
		if n.Ip.IP.To16() == nil {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "GnbIP is nil")
			return false
		}
		dstAddr := flowT.SliceToIPv6(n.Ip.IP.To16())
		ipv6.SrcAddr = srcAddr
		ipv6.DstAddr = dstAddr
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv6 src address%s,dst address %s", ipv6.SrcAddr, ipv6.DstAddr)

		// Fill L2
		currentPacket.Ether.EtherType = flowT.SwapIPV6Number
		currentPacket.Ether.SAddr = Ipport.MacAddress
		if Ipport.StaticARP {
			currentPacket.Ether.DAddr = Ipport.DstMacAddress
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv6 Static currentPacket.Ether.DAddr", currentPacket.Ether.DAddr)
		} else {
			// Find l2 addresses for new destionation IP in ndp cache
			// Next hop local exchange, targetIP is gnb ip
			targetIP := flowT.SliceToIPv6(n.Ip.IP.To16()) //ipv6.DstAddr
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv6 targetIP %s", targetIP)
			// Next hop gateway exchange, targetIP is gateway ip
			gwIp := configure.UpfConf.N3.Gateway
			if gwIp != defs.LocalExchangeGw {
				if net.ParseIP(gwIp).To16() == nil {
					rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "gnb gateway ip is nil")
					return false
				}
				targetIP = flowT.SliceToIPv6(net.ParseIP(gwIp).To16())
			}
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "gnb ip %s", n.Ip.IP)
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "gateway ip %s", gwIp)
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "lookup ipv6 targetIP %s", targetIP)

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
		// fill ip
		// Fill up l3
		ipv6.VtcFlow = 0x60
		ipv6.Proto = flowT.UDPNumber
		ipv6.HopLimits = 255

		length := currentPacket.GetPacketLen()
		ipv6.PayloadLen = packet.SwapBytesUint16(uint16(length - defs.UpfEtherLen - defs.UpfIPv6MinLen))
		//ipv6.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv6Checksum(ipv6))
		//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ipv6 head %+v", ipv6)

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
		//ipv6.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv6Checksum(ipv6))
		//udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(ipv6, udp, currentPacket.Data))
		//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ipv6 udp head %+v", udp)

		if !retVal {
			// 将报文先保存起来
			packet.GArpMutex.Lock()
			if packet.GArpBuffers.Len() > 200 {
				bufferHead := packet.GArpBuffers.Front()
				packet.GArpBuffers.Remove(bufferHead)
				packet.GArpMutex.Unlock()
				oldPacket := bufferHead.Value.(*packet.Packet)
				if err = packet.PacketCapture(nil, oldPacket, "other", "", packet.AbortPacket); err != nil { //arp 缓存区丢弃旧的包
					rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "packet:abort packet capture error:%s", err)
				}
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

			return false
		}
		// Send to network ，发送到N3对端
		currentPacket.SendPacket(Ipport.Index)
	} else {
		etherLen := uint(flowT.EtherLen)
		ipv4MinLen := uint(flowT.IPv4MinLen)
		UDPLen := uint(flowT.UDPLen)
		GTPMinLen := uint(flowT.GTPMinLen)
		GTPMinLen = 12
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil,
			"add gtp head,etherLen-ipv4MinLen-UDPLen-GTPMinLen", etherLen, ipv4MinLen, UDPLen, GTPMinLen)
		//length := currentPacket.GetPacketLen() - flowT.EtherLen
		// 创建 packet
		currentPacket, err := packet.NewArpBufPacket()
		if err != nil {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to NewPacket")
			return false
		}
		ok := packet.InitEmptyIPv4UDPPacket(currentPacket, uint(len(body)))
		if !ok {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to InitEmptyIPv4UDPPacket")
			return false
		}

		currentPacket.ParseL3()
		//非固定头填充
		currentPacket.PacketBytesChange(etherLen+ipv4MinLen+UDPLen, body)
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "change echo Message len=%d value: %#x", len(body), body)

		// 固定头填充
		// Fill new IPv4 header with addresses according to context
		ipv4 := currentPacket.GetIPv4NoCheck() //(*packet.IPv4Hdr)(currentPacket.L3)

		// 源IP，目的IP
		if len(ipport.IpPorts) <= int(ipport.N3Outport) {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil,
				"len of IpPorts %v", "N3Outport %v", len(ipport.IpPorts), ipport.N3Outport)
		}
		Ipport := ipport.IpPorts[ipport.N3Outport]
		srcAddr := Ipport.Subnet.IPv4.Addr
		if n.Ip.IP.To4() == nil {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "GnbIP is nil")
			return false
		}

		dstAddr := flowT.SliceToIPv4(n.Ip.IP.To4())
		ipv4.SrcAddr = srcAddr
		ipv4.DstAddr = dstAddr
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 src address%s,dst address %s", ipv4.SrcAddr, ipv4.DstAddr)

		// Fill L2
		currentPacket.Ether.EtherType = flowT.SwapIPV4Number
		currentPacket.Ether.SAddr = Ipport.MacAddress
		if Ipport.StaticARP {
			currentPacket.Ether.DAddr = Ipport.DstMacAddress
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 Static currentPacket.Ether.DAddr", currentPacket.Ether.DAddr)
		} else {
			// Find l2 addresses for new destionation IP in ARP cache
			// Next hop local exchange, targetIP is gnb ip
			targetIP := flowT.SliceToIPv4(n.Ip.IP.To4()) //ipv4.DstAddr
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 targetIP %s", targetIP)
			// Next hop gateway exchange, targetIP is gateway ip
			gwIp := configure.UpfConf.N3.Gateway
			if gwIp != defs.LocalExchangeGw {
				if net.ParseIP(gwIp).To4() == nil {
					rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "gnb gateway ip is nil")
					return false
				}
				targetIP = flowT.SliceToIPv4(net.ParseIP(gwIp).To4())
			}
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "gnb ip %s", n.Ip.IP)
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "gateway ip %s", gwIp)
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "lookup ipv4 targetIP %s", targetIP)

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

		// fill ip
		// Fill up l3
		ipv4.VersionIhl = 0x45
		ipv4.TypeOfService = 0
		ipv4.PacketID = 0xe803
		ipv4.FragmentOffset = 0
		ipv4.TimeToLive = 64

		length := currentPacket.GetPacketLen()
		ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - flowT.EtherLen))
		ipv4.NextProtoID = flowT.UDPNumber

		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 head %+v", ipv4)

		// fill udp
		// Fill up L4
		currentPacket.ParseL4ForIPv4()
		udp := currentPacket.GetUDPForIPv4()
		udp.SrcPort = packet.SwapUDPPortGTPU
		udp.DstPort = packet.SwapUDPPortGTPU
		udp.DgramLen = packet.SwapBytesUint16(uint16(length - flowT.EtherLen - flowT.IPv4MinLen))
		currentPacket.ParseL7(flowT.UDPNumber)
		// Calculate checksums
		//ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
		//udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, currentPacket.Data))
		ipv4.HdrChecksum = 0
		//ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
		udp.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4UDPCksum(ipv4, udp))
		currentPacket.SetTXIPv4UDPOLFlags(flowT.EtherLen, flowT.IPv4MinLen)
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "ipv4 udp head %+v", udp)

		if !retVal {
			// 将报文先保存起来
			packet.GArpMutex.Lock()
			if packet.GArpBuffers.Len() > 200 {
				bufferHead := packet.GArpBuffers.Front()
				packet.GArpBuffers.Remove(bufferHead)
				packet.GArpMutex.Unlock()
				oldPacket := bufferHead.Value.(*packet.Packet)
				if err = packet.PacketCapture(nil, oldPacket, "other", "", packet.AbortPacket); err != nil { //arp 缓存区丢弃旧的包
					rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "packet:abort packet capture error:%s", err)
				}
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

			return false
		}
		// Send to network ，发送到N3对端
		currentPacket.SendPacket(Ipport.Index)
	}
	return true
}

func EchoTimeoutRetransmission(n *gnbcontext.GnbInfo, data []byte) error {
	//rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//1、发送请求后，启动超时定时器
	cxt, cancel := context.WithCancel(context.Background())
	n.NTimer.T1RetransCancel = cancel
	t2 := time.NewTimer(gtpv1u.T2)
	var RetrCount = 0
	// 编码发送
	sendRet := sendEchoNffMsg(n, data)
	if sendRet == false {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.WARN, nil, "failed to gtp echo msg send")
	}
	metrics.UpfmoduleSet.EchoRequest.Inc(1)
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "gtp echo starts retransmission")
	for {
		select {
		case <-cxt.Done():
			//2、收到响应消息，关闭定时器
			t2.Stop()
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "turn off retransmission,echo")
			return nil
		case <-t2.C:
			if RetrCount == gtpv1u.MaxRetransT2 {
				//3、超时后，重发请求，发送3次，无响应，上报失败响应
				t2.Stop()
				// 对端没有响应，关闭echo发送，删除节点
				// 设置node的当前状态,上报smf 路径故障
				n.Start = false

				triggerUserPlanePathFailureReport(n)
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "no response from peer,echo %s", n.Ip.IP.String())
				// 关停当前gnb的echo
				if n.NTimer.T1Cancel != nil {
					n.NTimer.T1Cancel()
				}
				//todo 基站回送响应超时告警
				gnbReconnect, _ := upfam.GnbReconnect.Get(n.Ip.IP.String())
				if !gnbReconnect {
					alarmDetails := upfam.UPFAlarmDetails{
						Substring:   n.Ip.IP.String(),
						AlarmID:     am.UPFGnbHeartBeat,
						Reason:      "echo timeout",
						PeerAddress: n.Ip.String(),
						Suggestion:  "check gnb state",
					}
					upfam.UPFAlarmReport(alarmDetails) //基站回送响应超时告警
					upfam.GnbReconnect.Add(n.Ip.IP.String(), true)
				}
				return fmt.Errorf("timeout")
			}
			t2.Reset(gtpv1u.T2)
			{
				// 发送消息到 gnb
				sendRet := sendEchoNffMsg(n, data)
				if sendRet == false {
					rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to gtp echo msg send")
				}
				metrics.UpfmoduleSet.EchoRequest.Inc(1)
				RetrCount += 1
				Ipport := ipport.IpPorts[ipport.N3Outport]
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil,
					"Send echo to Peer : <%s>--><%s>: %#x\n", Ipport.Subnet.IPv4.Addr, n.Ip.IP, data)
			}
		}
	}
}

func triggerUserPlanePathFailureReport(n *gnbcontext.GnbInfo) {
	rlogger.FuncEntry(types.ModuleUpfServiceEcho, nil)
	// 向对应pfcp node 发送路径故障报告
	// 获取包含gnb信息的所有pfcp node id，并各自发送路径故障报告
	pfcpGnbList, err := pfcpgnbcontext.ValuesOfTbl()
	if err != nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to query pfcp gnb relation table")
		return
	}
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "up gnb ip(%s)", n.Ip.IP)
	for _, pfcpGnb := range pfcpGnbList {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "pfcp gnb list(%v)", pfcpGnb)
		// gnb在多个smf中
		if pfcpGnb.GnbNodeId == n.Ip.IP.String() {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO,
				nil, "gnb node id(%s),pfcp node id(%s)", pfcpGnb.GnbNodeId, pfcpGnb.PfcpNodeId)
			err := n4node.SendNodeReportRequest(pfcpGnb)
			if err != nil {
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "failed to node report send")
			}
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "succeeded to node report send")
			// 清理gnb 与pfcp节点关系表
			key := pfcpGnb.PfcpNodeId + pfcpGnb.GnbNodeId
			pfcpgnbcontext.Delete(key)
		}
	}
}
