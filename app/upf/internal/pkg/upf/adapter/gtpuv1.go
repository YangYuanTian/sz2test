package adapter

import (
	"bytes"
	"fmt"
	"github.com/intel-go/nff-go/packet"
	flowT "github.com/intel-go/nff-go/types"
	"lite5gc/cmn/message/gtpv1u"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/cmn/types3gpp"
	"lite5gc/upf/context/gnbcontext"
	"lite5gc/upf/context/ipport"
	"lite5gc/upf/context/pdrcontext"
	"lite5gc/upf/defs"
	"net"
	"unsafe"
)

func SendN3MsgHandleExt(PayloadMsgbuf []byte, Msgcxt *pdrcontext.DataFlowContext) ([]byte, error) {
	Msgcxt.Rw.RLock()
	if Msgcxt == nil {
		Msgcxt.Rw.RUnlock()
		//rlogger.Trace(moduleTag, types.ERROR, nil, "Input parameter check failed !")
		return nil, fmt.Errorf("Input parameter check failed !")
	}
	// Msgbuf 转换为GTPPDU，N6侧消息为Msg_Type_G_PDU，直接加GTPv1U协议头发送到N3侧
	// 需要获取RAN地址与通道信息
	N3EncodeMsg := &gtpv1u.GPDUSessionContDL{}

	N3EncodeMsg.Gtpbody = PayloadMsgbuf
	//填充GTPv1U协议头部
	N3EncodeMsg.Version = gtpv1u.Protocol_version
	N3EncodeMsg.PT = gtpv1u.Protocol_Type
	N3EncodeMsg.MessageType = gtpv1u.Msg_Type_G_PDU
	N3EncodeMsg.TEID = uint32(Msgcxt.GnbTEID) //0x80000000 //0x04180155

	// Msg_Type_G_PDU PDU_Type_DL_PDU_Session_Information
	N3EncodeMsg.EFlag = gtpv1u.Protocol_Present
	N3EncodeMsg.NextExtHeaderType = gtpv1u.ExtHT_PDU_SESSION_CONTAINER

	//N3EncodeMsg.PDUSessionContainer.DLPDUSession = Msgcxt.DP
	N3EncodeMsg.PDUSessionContainer.Length = 2
	N3EncodeMsg.PDUSessionContainer.PDUType = gtpv1u.PDU_Type_DL_PDU_Session_Information
	N3EncodeMsg.PDUSessionContainer.QFI = Msgcxt.DP.QFI //9 //10
	N3EncodeMsg.PDUSessionContainer.PPP = Msgcxt.DP.PPP
	N3EncodeMsg.PDUSessionContainer.PPI = Msgcxt.DP.PPI
	N3EncodeMsg.PDUSessionContainer.NextExtHeaderType = 0
	/*Octets 1  Extension Header Length
	2 – m		Extension Header Content
	m+1		     Next Extension Header Type
	*/
	Msgcxt.Rw.RUnlock()
	N3EncodeMsg.Length = (uint16(len(PayloadMsgbuf)) +
		uint16(gtpv1u.GTPV1_U_HEADER_OPTIONAL_FIELDS_LEN) +
		uint16(N3EncodeMsg.PDUSessionContainer.Length*4)) // 可c选头域9-12+ 扩展头+ payload length
	// test 删除IP与UDP头
	//N3EncodeMsg.Gtpbody = N3EncodeMsg.Gtpbody[28:]
	Msgbuf, err := N3EncodeMsg.EncodeMsg()
	if err != nil {
		//fmt.Println(err)
		//rlogger.Trace(moduleTag, types.ERROR, Msgcxt, "Failed to N6 message Eecode!")
		// N3DecodeMsg failed,discard message
		return Msgbuf, err
	}
	//fmt.Println(len(Msgbuf))
	//fmt.Printf("Encode value: %#x\n", Msgbuf)
	//rlogger.Trace(moduleTag, types.DEBUG, Msgcxt, "Encode value: %#x\n", Msgbuf)
	return Msgbuf, nil
}

func SendN3GTPUHandle(curPacket *packet.Packet, Msgcxt *pdrcontext.DataFlowContext) error {
	if configure.UpfConf.Adapter.GtpuExtheader == 1 {
		if (curPacket == nil) || (Msgcxt == nil) ||
			(!curPacket.EncapsulateHead(defs.UpfEtherLen, defs.UpfIPv4MinLen+defs.UpfUDPLen+defs.UpfGtp16Len)) {
			return fmt.Errorf("Input parameter check failed !")
		}
		// EncapsulateHead的时候修改了pkt_len和data_len
		length := uint16(curPacket.GetPacketLen() - (defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen + defs.UpfGtp16Len))
		GpduMsg := (*gtpv1u.GPDUSessionHdrDLOneExtHeader)(unsafe.Pointer(uintptr(unsafe.Pointer(curPacket.Ether)) + defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen))
		// 添加GTPU必选头内容
		GpduMsg.MHeaderType = gtpv1u.Protocol_version<<5 | //top 3 bits Version
			gtpv1u.Protocol_Type<<4 | //1 bits PT
			//gtpv1u.Protocol_Spare<<3 | //1 bits Spare
			gtpv1u.Protocol_Present<<2 //1 bits EFlag
		//gtpv1u.Protocol_SFlag<<1 | //1 SFlag
		//gtpv1u.Protocol_PNFlag     //1 PNFlag
		GpduMsg.MMessageType = gtpv1u.Msg_Type_G_PDU
		GpduMsg.MMessageLength = packet.SwapBytesUint16(length + defs.UpfGtp8AddLen)
		GpduMsg.MTeid = packet.SwapBytesUint32(uint32(Msgcxt.GnbTEID))
		// 添加GTPU可选头内容
		GpduMsg.OSequenceNumber = 0
		GpduMsg.ONPduNumber = 0
		GpduMsg.ONextExtensionHeader = gtpv1u.ExtHT_PDU_SESSION_CONTAINER
		// 添加GTPU扩展头内容
		GpduMsg.TLength = 1
		GpduMsg.TPduTypeSpareA = gtpv1u.PDU_Type_DL_PDU_Session_Information << 4
		GpduMsg.TPppRqiQfi = (Msgcxt.DP.PPP << 7) | // 1 bit PPP 第8位
			(Msgcxt.DP.RQI << 6 & 0x40) | //1 bit RQI 第7位
			(Msgcxt.DP.QFI & 0x3f) //6 bits QFI 后6位
		//GpduMsg.TPpiSpareB = Msgcxt.DP.PPI << 5
		//GpduMsg.Padding[0] = 0
		//GpduMsg.Padding[1] = 0
		//GpduMsg.Padding[2] = 0
		GpduMsg.TNextExtHeaderType = 0
	} else {
		if (curPacket == nil) || (Msgcxt == nil) ||
			(!curPacket.EncapsulateHead(defs.UpfEtherLen, defs.UpfIPv4MinLen+defs.UpfUDPLen+defs.UpfGtpLen)) {
			return fmt.Errorf("Input parameter check failed !")
		}
		// EncapsulateHead的时候修改了pkt_len和data_len
		length := uint16(curPacket.GetPacketLen() - (defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen + defs.UpfGtpLen))
		GpduMsg := (*gtpv1u.GPDUSessionHdrDL)(unsafe.Pointer(uintptr(unsafe.Pointer(curPacket.Ether)) + defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen))
		// 添加GTPU必选头内容
		GpduMsg.MHeaderType = gtpv1u.Protocol_version<<5 | //top 3 bits Version
			gtpv1u.Protocol_Type<<4 | //1 bits PT
			//gtpv1u.Protocol_Spare<<3 | //1 bits Spare
			gtpv1u.Protocol_Present<<2 //1 bits EFlag
		//gtpv1u.Protocol_SFlag<<1 | //1 SFlag
		//gtpv1u.Protocol_PNFlag     //1 PNFlag
		GpduMsg.MMessageType = gtpv1u.Msg_Type_G_PDU
		GpduMsg.MMessageLength = packet.SwapBytesUint16(length + defs.UpfGtpAddLen)
		GpduMsg.MTeid = packet.SwapBytesUint32(uint32(Msgcxt.GnbTEID))
		// 添加GTPU可选头内容
		GpduMsg.OSequenceNumber = 0
		GpduMsg.ONPduNumber = 0
		GpduMsg.ONextExtensionHeader = gtpv1u.ExtHT_PDU_SESSION_CONTAINER
		// 添加GTPU扩展头内容
		GpduMsg.TLength = 2
		GpduMsg.TPduTypeSpareA = gtpv1u.PDU_Type_DL_PDU_Session_Information << 4
		GpduMsg.TPppRqiQfi = (Msgcxt.DP.PPP << 7) | // 1 bit PPP 第8位
			(Msgcxt.DP.RQI << 6 & 0x40) | //1 bit RQI 第7位
			(Msgcxt.DP.QFI & 0x3f) //6 bits QFI 后6位
		GpduMsg.TPpiSpareB = Msgcxt.DP.PPI << 5
		GpduMsg.Padding[0] = 0
		GpduMsg.Padding[1] = 0
		GpduMsg.Padding[2] = 0
		GpduMsg.TNextExtHeaderType = 0
	}

	return nil
}

func SendN3GTPUHandleExtOnebyte(curPacket *packet.Packet, Msgcxt *pdrcontext.DataFlowContext) error {

	if (curPacket == nil) || (Msgcxt == nil) ||
		(!curPacket.EncapsulateHead(defs.UpfEtherLen, defs.UpfIPv4MinLen+defs.UpfUDPLen+defs.UpfGtpLen)) {
		return fmt.Errorf("Input parameter check failed !")
	}
	// EncapsulateHead的时候修改了pkt_len和data_len
	length := uint16(curPacket.GetPacketLen() - (defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen + defs.UpfGtpLen))
	GpduMsg := (*gtpv1u.GPDUSessionHdrDL)(unsafe.Pointer(uintptr(unsafe.Pointer(curPacket.Ether)) + defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen))
	// 添加GTPU必选头内容
	GpduMsg.MHeaderType = gtpv1u.Protocol_version<<5 | //top 3 bits Version
		gtpv1u.Protocol_Type<<4 | //1 bits PT
		//gtpv1u.Protocol_Spare<<3 | //1 bits Spare
		gtpv1u.Protocol_Present<<2 | //1 bits EFlag
		gtpv1u.Protocol_SFlag<<1 //1 SFlag
	//gtpv1u.Protocol_PNFlag     //1 PNFlag
	GpduMsg.MMessageType = gtpv1u.Msg_Type_G_PDU
	GpduMsg.MMessageLength = packet.SwapBytesUint16(length + defs.UpfGtp8AddLen)
	GpduMsg.MTeid = packet.SwapBytesUint32(uint32(Msgcxt.GnbTEID))
	// 添加GTPU可选头内容
	//atomic.AddInt32(&defs.SequenceNumber, 1)
	//
	//GpduMsg.OSequenceNumber = uint16(atomic.LoadInt32(&defs.SequenceNumber))
	GpduMsg.ONPduNumber = 0
	GpduMsg.ONextExtensionHeader = gtpv1u.ExtHT_PDU_SESSION_CONTAINER
	// 添加GTPU扩展头内容
	GpduMsg.TLength = 1
	GpduMsg.TPduTypeSpareA = gtpv1u.PDU_Type_DL_PDU_Session_Information << 4
	GpduMsg.TPppRqiQfi = (Msgcxt.DP.PPP << 7) | // 1 bit PPP 第8位
		(Msgcxt.DP.RQI << 6 & 0x40) | //1 bit RQI 第7位
		(Msgcxt.DP.QFI & 0x3f) //6 bits QFI 后6位
	//GpduMsg.TPpiSpareB = Msgcxt.DP.PPI << 5
	//GpduMsg.Padding[0] = 0
	//GpduMsg.Padding[1] = 0
	//GpduMsg.Padding[2] = 0
	GpduMsg.TNextExtHeaderType = 0
	return nil
}

func SendN3Ipv6GTPUHandle(curPacket *packet.Packet, Msgcxt *pdrcontext.DataFlowContext) error {

	if (curPacket == nil) || (Msgcxt == nil) ||
		(!curPacket.EncapsulateHead(defs.UpfEtherLen, defs.UpfIPv6MinLen+defs.UpfUDPLen+defs.UpfGtpLen)) {
		return fmt.Errorf("Input parameter check failed !")
	}
	// EncapsulateHead的时候修改了pkt_len和data_len
	length := uint16(curPacket.GetPacketLen() - (defs.UpfEtherLen + defs.UpfIPv6MinLen + defs.UpfUDPLen + defs.UpfGtpLen))
	GpduMsg := (*gtpv1u.GPDUSessionHdrDL)(unsafe.Pointer(uintptr(unsafe.Pointer(curPacket.Ether)) + defs.UpfEtherLen + defs.UpfIPv6MinLen + defs.UpfUDPLen))
	// 添加GTPU必选头内容
	GpduMsg.MHeaderType = gtpv1u.Protocol_version<<5 | //top 3 bits Version
		gtpv1u.Protocol_Type<<4 | //1 bits PT
		//gtpv1u.Protocol_Spare<<3 | //1 bits Spare
		gtpv1u.Protocol_Present<<2 //1 bits EFlag
	//gtpv1u.Protocol_SFlag<<1 | //1 SFlag
	//gtpv1u.Protocol_PNFlag     //1 PNFlag
	GpduMsg.MMessageType = gtpv1u.Msg_Type_G_PDU
	GpduMsg.MMessageLength = packet.SwapBytesUint16(length + defs.UpfGtpAddLen)
	GpduMsg.MTeid = packet.SwapBytesUint32(uint32(Msgcxt.GnbTEID))
	// 添加GTPU可选头内容
	GpduMsg.OSequenceNumber = 0
	GpduMsg.ONPduNumber = 0
	GpduMsg.ONextExtensionHeader = gtpv1u.ExtHT_PDU_SESSION_CONTAINER
	// 添加GTPU扩展头内容
	GpduMsg.TLength = 2
	GpduMsg.TPduTypeSpareA = gtpv1u.PDU_Type_DL_PDU_Session_Information << 4
	GpduMsg.TPppRqiQfi = (Msgcxt.DP.PPP << 7) | // 1 bit PPP 第8位
		(Msgcxt.DP.RQI << 6 & 0x40) | //1 bit RQI 第7位
		(Msgcxt.DP.QFI & 0x3f) //6 bits QFI 后6位
	GpduMsg.TPpiSpareB = Msgcxt.DP.PPI << 5
	GpduMsg.Padding[0] = 0
	GpduMsg.Padding[1] = 0
	GpduMsg.Padding[2] = 0
	GpduMsg.TNextExtHeaderType = 0
	return nil
}

// 解码优化
func GetTeidFromGtpPacket(currentPacket *packet.Packet) (uint32, error) {
	gtpuHdrUl := (*gtpv1u.GPDUSessionHdrUL)(unsafe.Pointer(uintptr(unsafe.Pointer(currentPacket.Ether)) +
		defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen))
	return packet.SwapBytesUint32(gtpuHdrUl.MTeid), nil
}
func RecvN3MsgHandleV1(currentPacket *packet.Packet, msgCxt *pdrcontext.DataFlowContext) ([]byte, error) {
	//N3DecodeMsg := &gtpv1_u.N3MsgParser{Msgbuf:[]byte{}}
	Msgbuf, _ := currentPacket.GetPacketPayload()
	N3DecodeMsg := &gtpv1u.N3MsgParser{Msgbuf: Msgbuf}
	rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, msgCxt, "N3 receive packet %#x", Msgbuf)

	// 分割gtp与body
	//安全检查
	if len(Msgbuf) < gtpv1u.GTPV1_U_HEADER_MIN_LEN {
		return nil, gtpv1u.ErrGTPMsgLen
	}

	GtpMsg := &gtpv1u.GTPPDU{Gtpv1uHeader: gtpv1u.Gtpv1uHeader{}}
	N3DecodeMsg.GtpuMsg = GtpMsg
	//make([]byte, len(m.Msgbuf)),
	//length := uint16(currentPacket.GetPacketLen() - (defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen + defs.UpfGtpLen))
	gtpuHdrUl := (*gtpv1u.GPDUSessionHdrUL)(unsafe.Pointer(uintptr(unsafe.Pointer(currentPacket.Ether)) +
		defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen))

	// Always present fields
	// 1 Octet
	GtpMsg.Version = gtpuHdrUl.MHeaderType >> 5
	//top 3 bits
	GtpMsg.PT = gtpuHdrUl.MHeaderType >> 4 & 1
	// 1 bit
	GtpMsg.Spare = gtpuHdrUl.MHeaderType >> 3 & 1
	// 1 bit
	GtpMsg.EFlag = gtpuHdrUl.MHeaderType >> 2 & 1
	// 1 bit
	GtpMsg.SFlag = gtpuHdrUl.MHeaderType >> 1 & 1
	// 1 bit
	GtpMsg.PNFlag = gtpuHdrUl.MHeaderType & 1
	// 1 bit
	// Message Type 2 Octet
	GtpMsg.MessageType = gtpuHdrUl.MMessageType
	//Length 3-4 Octet
	GtpMsg.Length = packet.SwapBytesUint16(gtpuHdrUl.MMessageLength)
	//Tunnel Endpoint Identifier 5-8 Octet
	GtpMsg.TEID = packet.SwapBytesUint32(gtpuHdrUl.MTeid)
	// gtp header长度是8,无可选头
	if GtpMsg.EFlag != gtpv1u.Protocol_Present &&
		GtpMsg.SFlag != gtpv1u.Protocol_Present &&
		GtpMsg.PNFlag != gtpv1u.Protocol_Present {
		N3DecodeMsg.OffSet = 8
		if GtpMsg.MessageType == gtpv1u.Msg_Type_End_Marker {
			msgCxt.UpfTEID = types3gpp.Teid(GtpMsg.TEID)
			return nil, gtpv1u.ErrIsEndMarker
		}
		msgCxt.UpfTEID = types3gpp.Teid(GtpMsg.TEID)
		return Msgbuf[8:], nil
	}

	if len(Msgbuf) < defs.UpfGtpAddLen {
		return Msgbuf[8:], gtpv1u.ErrExtHeaderType
	}
	// //Optional fields
	if GtpMsg.EFlag == gtpv1u.Protocol_Present ||
		GtpMsg.SFlag == gtpv1u.Protocol_Present ||
		GtpMsg.PNFlag == gtpv1u.Protocol_Present {
		GtpMsg.SequenceNumber = packet.SwapBytesUint16(gtpuHdrUl.OSequenceNumber)
		GtpMsg.NPDUNumber = gtpuHdrUl.ONPduNumber
		GtpMsg.NextExtHeaderType = gtpuHdrUl.ONextExtensionHeader
		// Optional fields S,PN,E的长度，默认值是4bytes
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "  9-10 Octet SequenceNumber:%d", GtpMsg.SequenceNumber)
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "  11 Octet NPDUNumber:%d", GtpMsg.NPDUNumber)
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "  12 Octet NextExtHeaderType:%d", GtpMsg.NextExtHeaderType)
	}

	// 扩展头域解析,根据GtpMsg.MessageType解析head与IE
	// 以业务消息类型控制解析的头域,
	// 无扩展头域，直接返回成功nil
	N3DecodeMsg.OffSet = 12
	if GtpMsg.NextExtHeaderType == 0 &&
		GtpMsg.MessageType == gtpv1u.Msg_Type_G_PDU {
		return Msgbuf[12:], nil
	}

	err := gtpv1u.GtpuExtensionHeaderV1(gtpuHdrUl, N3DecodeMsg)
	if err != nil {
		//fmt.Println(err)
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
		return nil, err
	}

	rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, msgCxt, "gtp header %+v !", &GtpMsg.Gtpv1uHeader)
	rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, msgCxt, "gtp body offset %d !", uint8(N3DecodeMsg.OffSet))

	N3DecodeMsg.GtpuMsg.Gtpbody = N3DecodeMsg.Msgbuf[N3DecodeMsg.OffSet:]
	// 获取gNB带来的teid与QFI
	if N3DecodeMsg.GtpuMsg.MessageType == gtpv1u.Msg_Type_G_PDU {
		if N3DecodeMsg.GPDUSessionUL != nil {
			msgCxt.UpfTEID = types3gpp.Teid(N3DecodeMsg.GPDUSessionUL.TEID)
			//msgCxt.Msgcxt.UpfIP = N3DecodeMsg.GPDUSessionUL
			msgCxt.UP = N3DecodeMsg.GPDUSessionUL.PDUSessionContainer.ULPDU
			return N3DecodeMsg.GtpuMsg.Gtpbody, nil
		} else {
			//TODO pass when fail // No extension header
			msgCxt.UpfTEID = types3gpp.Teid(N3DecodeMsg.GtpuMsg.TEID)
			return N3DecodeMsg.GtpuMsg.Gtpbody, nil
		}

	}
	// 其他node消息
	// IE 解析
	if N3DecodeMsg.GtpuMsg.MessageType != gtpv1u.Msg_Type_G_PDU {
		// 去掉网卡补齐位（IP包46）
		if N3DecodeMsg.GtpuMsg.MessageType == gtpv1u.Msg_Type_Echo_Response {
			gtpLen := int(gtpv1u.GTPV1_U_HEADER_MIN_LEN + N3DecodeMsg.GtpuMsg.Length)
			if gtpLen > len(N3DecodeMsg.Msgbuf) {
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, fmt.Errorf("invalid message")
			}
			r := bytes.NewReader(N3DecodeMsg.Msgbuf[12:gtpLen])
			err := N3DecodeMsg.GtpuInformationElement(r, r.Len()) //GtpuInformationElement(r *bytes.Reader, residualLen int) error
			if err != nil {
				//fmt.Println(err)
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, err
			}

			msgCxt.GtpMsg = N3DecodeMsg

			return nil, nil
		}
		if N3DecodeMsg.GtpuMsg.MessageType == gtpv1u.Msg_Type_Echo_Request {
			rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "echo request")
			gtpLen := int(gtpv1u.GTPV1_U_HEADER_MIN_LEN + N3DecodeMsg.GtpuMsg.Length)
			if gtpLen > len(N3DecodeMsg.Msgbuf) {
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, fmt.Errorf("invalid message")
			}
			r := bytes.NewReader(N3DecodeMsg.Msgbuf[12:gtpLen])
			err := N3DecodeMsg.GtpuInformationElement(r, r.Len()) //GtpuInformationElement(r *bytes.Reader, residualLen int) error
			if err != nil {
				//fmt.Println(err)
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, err
			}

			msgCxt.GtpMsg = N3DecodeMsg

			return nil, nil
		}
	}

	return N3DecodeMsg.GtpuMsg.Gtpbody, nil
}

func EchoRequestCreate(n *gnbcontext.GnbInfo) ([]byte, error) {
	n.SequenceNumber += 1

	N3EncodeMsg := &gtpv1u.EchoRequest{}

	//填充GTPv1U协议头部
	N3EncodeMsg.Version = gtpv1u.Protocol_version
	N3EncodeMsg.PT = gtpv1u.Protocol_Type
	N3EncodeMsg.SFlag = gtpv1u.Protocol_Present
	N3EncodeMsg.MessageType = gtpv1u.Msg_Type_Echo_Request
	N3EncodeMsg.TEID = 0

	N3EncodeMsg.SequenceNumber = n.SequenceNumber

	N3EncodeMsg.Length = uint16(gtpv1u.GTPV1_U_HEADER_OPTIONAL_FIELDS_LEN)

	N3EncodeMsg.IE.IsPresence = false
	// test 删除IP与UDP头
	//N3EncodeMsg.Gtpbody = N3EncodeMsg.Gtpbody[28:]
	Msgbuf, err := N3EncodeMsg.EncodeMsg()
	if err != nil {
		//fmt.Println(err)
		//rlogger.Trace(moduleTag, types.ERROR, Msgcxt, "Failed to N6 message Eecode!")
		// N3DecodeMsg failed,discard message
		return Msgbuf, err
	}
	//fmt.Println(len(Msgbuf))
	//fmt.Printf("Encode value: %#x\n", Msgbuf)
	//rlogger.Trace(moduleTag, types.DEBUG, Msgcxt, "Encode value: %#x\n", Msgbuf)
	return Msgbuf, nil
}

func EndMarkerCreate(n *gnbcontext.GnbInfo, teid types3gpp.Teid) ([]byte, error) {
	n.SequenceNumber += 1
	N3EncodeMsg := &gtpv1u.EchoRequest{}

	//填充GTPv1U协议头部
	N3EncodeMsg.Version = gtpv1u.Protocol_version
	N3EncodeMsg.PT = gtpv1u.Protocol_Type
	N3EncodeMsg.MessageType = gtpv1u.Msg_Type_End_Marker
	N3EncodeMsg.TEID = uint32(teid)

	N3EncodeMsg.SequenceNumber = n.SequenceNumber

	N3EncodeMsg.Length = uint16(gtpv1u.GTPV1_U_HEADER_OPTIONAL_FIELDS_LEN)

	N3EncodeMsg.IE.IsPresence = false
	// test 删除IP与UDP头
	//N3EncodeMsg.Gtpbody = N3EncodeMsg.Gtpbody[28:]
	Msgbuf, err := N3EncodeMsg.EncodeMsg()
	if err != nil {
		//fmt.Println(err)
		//rlogger.Trace(moduleTag, types.ERROR, Msgcxt, "Failed to N6 message Eecode!")
		// N3DecodeMsg failed,discard message
		return Msgbuf, err
	}
	//fmt.Println(len(Msgbuf))
	//fmt.Printf("Encode value: %#x\n", Msgbuf)
	//rlogger.Trace(moduleTag, types.DEBUG, Msgcxt, "Encode value: %#x\n", Msgbuf)
	return Msgbuf, nil
}

func SendEndMarker(currentPacket *packet.Packet, gnbIP net.IP) bool {
	retVal := true
	// Fill new IPv4 header with addresses according to context
	ipv4 := currentPacket.GetIPv4NoCheck() //(*packet.IPv4Hdr)(currentPacket.L3)

	// 源IP，目的IP
	if len(ipport.IpPorts) <= int(ipport.N3Outport) {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil,
			"len of IpPorts %v", "N3Outport %v", len(ipport.IpPorts), ipport.N3Outport)
	}
	Ipport := ipport.IpPorts[ipport.N3Outport]
	srcAddr := Ipport.Subnet.IPv4.Addr
	if gnbIP.To4() == nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "GnbIP is nil")
		return false
	}
	dstAddr := flowT.SliceToIPv4(gnbIP.To4())
	ipv4.SrcAddr = srcAddr
	ipv4.DstAddr = dstAddr
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "Ipv4 src address%s,dst address %s", ipv4.SrcAddr, ipv4.DstAddr)

	// Fill L2
	currentPacket.Ether.EtherType = flowT.SwapIPV4Number
	currentPacket.Ether.SAddr = Ipport.MacAddress
	if Ipport.StaticARP {
		currentPacket.Ether.DAddr = Ipport.DstMacAddress
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "Ipv4 Static currentPacket.Ether.DAddr", currentPacket.Ether.DAddr)
	} else {
		// Find l2 addresses for new destionation IP in ARP cache
		// Next hop local exchange, targetIP is gnb ip
		targetIP := flowT.SliceToIPv4(gnbIP.To4()) //ipv4.DstAddr
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "Ipv4 targetIP %s", targetIP)
		// Next hop gateway exchange, targetIP is gateway ip
		gwIp := configure.UpfConf.N3.Gateway
		if gwIp != defs.LocalExchangeGw {
			if net.ParseIP(gwIp).To4() == nil {
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "Gnb gateway ip is nil")
				return false
			}
			targetIP = flowT.SliceToIPv4(net.ParseIP(gwIp).To4())
		}
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "Gnb ip %s", gnbIP)
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "Gateway ip %s", gwIp)
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "Lookup ipv4 targetIP %s", targetIP)

		targetMAC, found := Ipport.NeighCache.LookupMACForIPv4(targetIP)
		if !found {
			// fmt.Println("Not found MAC address for IP", targetIP.String())
			Ipport.NeighCache.SendARPRequestForIPv4(targetIP, ipv4.SrcAddr, 0)
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "Ipv4 targetIP %s, ipv4 SrcAddr %s,", targetIP, ipv4.SrcAddr)
			retVal = false
		}
		currentPacket.Ether.DAddr = targetMAC
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, nil, "Ipv4 current packet.Ether.DAddr %s", currentPacket.Ether.DAddr)

	}
	if !retVal {
		// 将报文先保存起来
		packet.GArpMutex.Lock()
		if packet.GArpBuffers.Len() > 200 {
			bufferHead := packet.GArpBuffers.Front()
			packet.GArpBuffers.Remove(bufferHead)
			packet.GArpMutex.Unlock()
			oldPacket := bufferHead.Value.(*packet.Packet)
			err := packet.PacketCapture(nil, currentPacket, "other", "", packet.AbortPacket) //arp缓存丢包
			if err != nil {
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "packet:abort packet capture error:%s", err)
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
	return true
}

func SendEndMarkerIpv6(currentPacket *packet.Packet, gnbIP net.IP) bool {
	retVal := true
	ipv6 := currentPacket.GetIPv6NoCheck() //(*packet.IPv6Hdr)(currentPacket.L3)

	// 源IP，目的IP
	if len(ipport.IpPorts) <= int(ipport.N3Outport) {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil,
			"len of IpPorts %v", "N3Outport %v", len(ipport.IpPorts), ipport.N3Outport)
	}
	Ipport := ipport.IpPorts[ipport.N3Outport]
	srcAddr := Ipport.Subnet.IPv6.Addr
	if gnbIP.To16() == nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "GnbIP is nil")
		return false
	}
	dstAddr := flowT.SliceToIPv6(gnbIP.To16())
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
		// Find l2 addresses for new destionation IP in ARP cache
		// Next hop local exchange, targetIP is gnb ip
		targetIP := flowT.SliceToIPv6(gnbIP.To16()) //ipv6.DstAddr
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
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "gnb ip %s", gnbIP)
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
			arpPacket.SetTXIPv6UDPOLFlags(flowT.EtherLen, flowT.IPv6Len)

			packet.GArpMutex.Lock()
			packet.GArpBuffers.PushBack(arpPacket)
			packet.GArpMutex.Unlock()
		}

		return false
	}

	// Send to network ，发送到N3对端
	currentPacket.SendPacket(Ipport.Index)
	return true
}

// ipv6流程
func RecvN3MsgIpv6HandleV1(currentPacket *packet.Packet, msgCxt *pdrcontext.DataFlowContext) ([]byte, error) {
	//N3DecodeMsg := &gtpv1_u.N3MsgParser{Msgbuf:[]byte{}}
	Msgbuf, _ := currentPacket.GetPacketPayload()
	N3DecodeMsg := &gtpv1u.N3MsgParser{Msgbuf: Msgbuf}

	// 分割gtp与body
	//安全检查
	if len(Msgbuf) < gtpv1u.GTPV1_U_HEADER_MIN_LEN {
		return nil, gtpv1u.ErrGTPMsgLen
	}

	GtpMsg := &gtpv1u.GTPPDU{Gtpv1uHeader: gtpv1u.Gtpv1uHeader{}}
	N3DecodeMsg.GtpuMsg = GtpMsg
	//make([]byte, len(m.Msgbuf)),
	//length := uint16(currentPacket.GetPacketLen() - (defs.UpfEtherLen + defs.UpfIPv4MinLen + defs.UpfUDPLen + defs.UpfGtpLen))
	gtpuHdrUl := (*gtpv1u.GPDUSessionHdrUL)(unsafe.Pointer(uintptr(unsafe.Pointer(currentPacket.Ether)) +
		defs.UpfEtherLen + defs.UpfIPv6MinLen + defs.UpfUDPLen))

	// Always present fields
	// 1 Octet
	GtpMsg.Version = gtpuHdrUl.MHeaderType >> 5
	//top 3 bits
	GtpMsg.PT = gtpuHdrUl.MHeaderType >> 4 & 1
	// 1 bit
	GtpMsg.Spare = gtpuHdrUl.MHeaderType >> 3 & 1
	// 1 bit
	GtpMsg.EFlag = gtpuHdrUl.MHeaderType >> 2 & 1
	// 1 bit
	GtpMsg.SFlag = gtpuHdrUl.MHeaderType >> 1 & 1
	// 1 bit
	GtpMsg.PNFlag = gtpuHdrUl.MHeaderType & 1
	// 1 bit
	// Message Type 2 Octet
	GtpMsg.MessageType = gtpuHdrUl.MMessageType
	//Length 3-4 Octet
	GtpMsg.Length = packet.SwapBytesUint16(gtpuHdrUl.MMessageLength)
	//Tunnel Endpoint Identifier 5-8 Octet
	GtpMsg.TEID = packet.SwapBytesUint32(gtpuHdrUl.MTeid)
	// gtp header长度是8,无可选头
	if GtpMsg.EFlag != gtpv1u.Protocol_Present &&
		GtpMsg.SFlag != gtpv1u.Protocol_Present &&
		GtpMsg.PNFlag != gtpv1u.Protocol_Present {
		N3DecodeMsg.OffSet = 8
		if GtpMsg.MessageType == gtpv1u.Msg_Type_End_Marker {
			msgCxt.UpfTEID = types3gpp.Teid(gtpuHdrUl.MTeid)
			return nil, gtpv1u.ErrIsEndMarker
		}
		return Msgbuf[8:], nil
	}

	if len(Msgbuf) < defs.UpfGtpAddLen {
		return Msgbuf[8:], gtpv1u.ErrExtHeaderType
	}
	// //Optional fields
	if GtpMsg.EFlag == gtpv1u.Protocol_Present ||
		GtpMsg.SFlag == gtpv1u.Protocol_Present ||
		GtpMsg.PNFlag == gtpv1u.Protocol_Present {
		GtpMsg.SequenceNumber = packet.SwapBytesUint16(gtpuHdrUl.OSequenceNumber)
		GtpMsg.NPDUNumber = gtpuHdrUl.ONPduNumber
		GtpMsg.NextExtHeaderType = gtpuHdrUl.ONextExtensionHeader
		// Optional fields S,PN,E的长度，默认值是4bytes
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "  9-10 Octet SequenceNumber:%d", GtpMsg.SequenceNumber)
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "  11 Octet NPDUNumber:%d", GtpMsg.NPDUNumber)
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, nil, "  12 Octet NextExtHeaderType:%d", GtpMsg.NextExtHeaderType)
	}

	// 扩展头域解析,根据GtpMsg.MessageType解析head与IE
	// 以业务消息类型控制解析的头域,
	// 无扩展头域，直接返回成功nil
	N3DecodeMsg.OffSet = 12
	if GtpMsg.NextExtHeaderType == 0 &&
		GtpMsg.MessageType == gtpv1u.Msg_Type_G_PDU {
		return Msgbuf[12:], nil
	}

	err := gtpv1u.GtpuExtensionHeaderV1(gtpuHdrUl, N3DecodeMsg)
	if err != nil {
		//fmt.Println(err)
		rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
		return nil, err
	}

	rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, msgCxt, "gtp header %+v !", &GtpMsg.Gtpv1uHeader)
	rlogger.Trace(types.ModuleUpfAdapter, rlogger.DEBUG, msgCxt, "gtp body offset %d !", uint8(N3DecodeMsg.OffSet))

	N3DecodeMsg.GtpuMsg.Gtpbody = N3DecodeMsg.Msgbuf[N3DecodeMsg.OffSet:]
	// 获取gNB带来的teid与QFI
	if N3DecodeMsg.GtpuMsg.MessageType == gtpv1u.Msg_Type_G_PDU {
		if N3DecodeMsg.GPDUSessionUL != nil {
			msgCxt.UpfTEID = types3gpp.Teid(N3DecodeMsg.GPDUSessionUL.TEID)
			//msgCxt.Msgcxt.UpfIP = N3DecodeMsg.GPDUSessionUL
			msgCxt.UP = N3DecodeMsg.GPDUSessionUL.PDUSessionContainer.ULPDU
			return N3DecodeMsg.GtpuMsg.Gtpbody, nil
		} else {
			//TODO pass when fail // No extension header
			msgCxt.UpfTEID = types3gpp.Teid(N3DecodeMsg.GtpuMsg.TEID)
			return N3DecodeMsg.GtpuMsg.Gtpbody, nil
		}

	}
	// 其他node消息
	// IE 解析
	if N3DecodeMsg.GtpuMsg.MessageType != gtpv1u.Msg_Type_G_PDU {
		// 去掉网卡补齐位（IP包46）
		if N3DecodeMsg.GtpuMsg.MessageType == gtpv1u.Msg_Type_Echo_Response {
			gtpLen := int(gtpv1u.GTPV1_U_HEADER_MIN_LEN + N3DecodeMsg.GtpuMsg.Length)
			if gtpLen > len(N3DecodeMsg.Msgbuf) {
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, fmt.Errorf("invalid message")
			}
			r := bytes.NewReader(N3DecodeMsg.Msgbuf[12:gtpLen])
			err := N3DecodeMsg.GtpuInformationElement(r, r.Len()) //GtpuInformationElement(r *bytes.Reader, residualLen int) error
			if err != nil {
				//fmt.Println(err)
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, err
			}

			msgCxt.GtpMsg = N3DecodeMsg

			return nil, nil
		}
		if N3DecodeMsg.GtpuMsg.MessageType == gtpv1u.Msg_Type_Echo_Request {
			gtpLen := int(gtpv1u.GTPV1_U_HEADER_MIN_LEN + N3DecodeMsg.GtpuMsg.Length)
			if gtpLen > len(N3DecodeMsg.Msgbuf) {
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, fmt.Errorf("invalid message")
			}
			r := bytes.NewReader(N3DecodeMsg.Msgbuf[12:gtpLen])
			err := N3DecodeMsg.GtpuInformationElement(r, r.Len()) //GtpuInformationElement(r *bytes.Reader, residualLen int) error
			if err != nil {
				//fmt.Println(err)
				rlogger.Trace(types.ModuleUpfAdapter, rlogger.WARN, nil, " Error: %s", err)
				return nil, err
			}

			msgCxt.GtpMsg = N3DecodeMsg

			return nil, nil
		}
	}

	return N3DecodeMsg.GtpuMsg.Gtpbody, nil
}
