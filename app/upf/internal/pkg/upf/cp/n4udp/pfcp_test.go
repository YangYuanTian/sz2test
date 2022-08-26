package n4udp_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"
	"upf/internal/pkg/cmn/message/pfcp"
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
	"upf/internal/pkg/upf/cp/n4layer"
	. "upf/internal/pkg/upf/cp/n4udp"
)

//func TestUpfN4ResponseMsg(t *testing.T) {
//	upfCtxt := &types.AppContext{
//		Name:     "upf",
//		Wg:       &sync.WaitGroup{},
//		ConfPath: types.DEF_CONF_FILE_UPF,
//	}
//	upfCtxt.Ctx, upfCtxt.Cancel = context.WithCancel(context.Background())
//	//load common configuration from amf config file
//	err := configure.LoadConfigCmn("ini", types.DEF_CONF_FILE_UPF)
//	if err != nil {
//		panic("load common config file failed")
//	}
//
//	//load config
//	var confPath = types.DEF_CONF_FILE_UPF
//	err = configure.LoadConfigUPF("ini", confPath)
//	if err != nil {
//		panic("load upf config file failed")
//	}
//
//	////tag
//	//start rlogger
//	//rlogger.Init(configure.CmnConf.rlogger.LogPath, configure.CmnConf.rlogger.LogLevel)
//	rlogger.Init()
//
//	// 当前开启N4 tcp server
//	errN4 := StartN4Server(upfCtxt)
//	if errN4 != nil {
//		panic("Failed to start n4 socket server ")
//	}
//
//	time.Sleep(30e9)
//	n4layer.N4SessionReportRequest(nil, nil)
//	upfCtxt.Wg.Wait()
//}

// PFCP Association Setup Request (5)
// upf side
func TestPfcpUnmarshal5(t *testing.T) {
	//PFCP Association Setup Request (5)
	data, _ := hex.DecodeString("2005001500000100003c0005000aca610200600004e07227a1")
	fmt.Printf("%x\n", data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 5
	//Length: 21
	//SequenceNumber: 1
	if msg.Header.MessageType != 5 || msg.Header.Length != 21 ||
		msg.Header.SequenceNumber != 1 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.PFCPAssociationSetupRequest)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	//10.202.97.2
	//2019-04-30 01:47:13 +0000 UTC
	fmt.Println(net.IP(v.IE.NodeID.NodeIDvalue))
	fmt.Println(v.IE.RecoveryTimeStamp.RecoveryTimeStamp.UTC())

	fmt.Println("------response------")

	//配置参数设置
	n4layer.UpfN4Layer.UpfIp = "10.202.94.2"
	n4layer.UpfN4Layer.N3Ip = "10.202.94.2"

	res := &pfcpv1.Message{}

	Dispatch(nil, msg, res)

	//设置测试参数
	response, ok := res.Body.(*pfcp.PFCPAssociationSetupResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	response.IE.NodeID.NodeIDvalue = []byte{10, 202, 94, 2}
	response.IE.RecoveryTimeStamp.RecoveryTimeStamp = time.Unix(1556588833, 0)

	response.IE.IeFlags.Clear(pfcp.IeTypeUserPlaneIPResourceInformation)

	fmt.Println(response.IE.RecoveryTimeStamp.RecoveryTimeStamp.UTC())
	// todo pfcp encode
	data, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("2006001a00000100003c0005000aca5e02001300010100600004e07227a1")
	//"2006001600      003c0005000aca5e02001300010100600004e07227a1"
	//2006001600000100003c0005000aca5e02001300010100600004e07227a1
	fmt.Printf("%x\n", data)

	if !bytes.Equal(ExpectedData, data) {
		t.Errorf("Pfcp marshal failed")
	}
}

// Message Type: PFCP Association Setup Response (6)
// amf side
func TestPfcpUnmarshal6(t *testing.T) {
	//PFCP Association Setup Request (5)
	ExpectedReqdata, _ := hex.DecodeString("2005001500000100003c0005000aca610200600004e07227a1")
	//请求编码
	req := pfcpv1.Message{}
	request := &pfcp.PFCPAssociationSetupRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Association_Setup_Request,
			Length:         0, // todo 编码后填充
			SequenceNumber: 1},
	}
	request.IE = &pfcp.IEPFCPAssociationSetupRequest{}
	request.IE.NodeID = &pfcp.IENodeID{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeNodeID,
			Length: 5,
		},
		NodeIDType:  0,
		NodeIDvalue: []byte{10, 202, 97, 2}, // amf ip
	}

	request.IE.RecoveryTimeStamp = &pfcp.IERecoveryTimeStamp{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeRecoveryTimeStamp,
			Length: 4,
		},
		// 1556588833 = nt64(0xe07227a1(wireshark) - 0x83aa7e80(1900到1970的秒差))
		RecoveryTimeStamp: time.Unix(1556588833, 0),
	}
	req.Header.Version = request.PfcpHeader.Version
	req.Header.MessageType = pfcp.PFCP_Association_Setup_Request
	req.Header.SequenceNumber = request.PfcpHeader.SequenceNumber
	//todo 编码后填充
	req.Header.Length = 0
	req.Body = request
	fmt.Println(req.String())

	// todo pfcp encode
	data, err := req.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal err %s", err)
	}
	fmt.Printf("%x\n", ExpectedReqdata)
	fmt.Printf("%x\n", data)
	if !bytes.Equal(data, ExpectedReqdata) {
		t.Errorf("Pfcp msg marshal failed")
	}
	fmt.Println("------response------")
	// 响应解码
	resdata, _ := hex.DecodeString("2006001a00000100003c0005000aca5e02001300010100600004e07227a1")
	fmt.Printf("resdata:%x\n", resdata)
	msg := pfcpv1.Message{}
	msg.Unmarshal(resdata)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 6
	//Length: 26
	//SequenceNumber: 1
	if msg.Header.MessageType != 6 || msg.Header.Length != 26 ||
		msg.Header.SequenceNumber != 1 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.PFCPAssociationSetupResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	// 消息头填充
	v.PfcpHeader.Version = msg.Header.Version
	v.PfcpHeader.MessageType = msg.Header.MessageType
	v.PfcpHeader.Length = msg.Header.Length
	v.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber

	//10.202.97.2
	//2019-04-30 01:47:13 +0000 UTC
	fmt.Println(net.IP(v.IE.NodeID.NodeIDvalue))
	fmt.Println((v.IE.Cause.CauseValue))
	fmt.Println(v.IE.RecoveryTimeStamp.RecoveryTimeStamp.UTC())

	err = Dispatch(nil, msg, nil)
	if err != nil {
		t.Errorf("Pfcp msg handler err %s", err)
	}
	// upf ip
	if net.IP(v.IE.NodeID.NodeIDvalue).String() != "10.202.94.2" ||
		v.IE.RecoveryTimeStamp.RecoveryTimeStamp.UTC().String() != "2019-04-30 01:47:13 +0000 UTC" {
		t.Errorf("Pfcp header unmarshal failed")
	}
}

// Message Type: PFCP Session Establishment Request (50)
// upf side
func TestPfcpUnmarshal50(t *testing.T) {
	//PFCP Session Establishment Request (50)
	data, _ := hex.DecodeString("2132013d000000000000000000000200003c0005000aca6102" +
		"0039000d0200000000000027100aca610200010078003800020001001d0004000000ff0002005" +
		"100140001000015000901000000010aca5e0100170036010000327065726d6974206f75742031" +
		"362066726f6d20616e79203530303020746f2061737369676e656420313032352d36353533350" +
		"07c000101005f000100006c000400000001006d00040000000100010035003800020002001d00" +
		"04000000ff000200130014000101005d00050601010101007c000101006c000400000002006d0" +
		"0040000000100030016006c000400000001002c00010200040005002a00010100030012006c00" +
		"0400000002002c00010c005800010100550005005800010100070020006d00040000000100190" +
		"00100001a000a00000000010000000001007c0001010071000101")
	// 总长 321=4+317
	fmt.Printf("%x\n", data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 1
	//Message Type: 50
	//Length: 317
	//Seid: 0x0000000000000000
	//SequenceNumber: 2
	if msg.Header.MessageType != 50 || msg.Header.Length != 317 ||
		msg.Header.SequenceNumber != 2 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.SessionEstablishmentRequest)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	//10.202.97.2
	//2019-04-30 01:47:13 +0000 UTC
	fmt.Println(net.IP(v.IE.NodeID.NodeIDvalue))
	fmt.Println(v.IE.CPFSEID.SEID)

	fmt.Println("------response------")
	// 响应编码
	res := &pfcpv1.Message{}

	//配置参数设置
	n4layer.UpfN4Layer.UpfIp = "10.202.94.2"
	Dispatch(nil, msg, res)
	// todo pfcp encode
	//设置SEID的值为测试值
	resTmp, ok := res.Body.(*pfcp.SessionEstablishmentResponse)
	if !ok {
		t.Errorf("Pfcp body marshal failed")
	}
	resTmp.IE.UPFSEID.SEID = 0x0000000000004e20
	resdata, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("2133002b000000000000271000000200003c000500" +
		"0aca5e0200130001010039000d020000000000004e200aca5e02")
	fmt.Printf("result  :%x\n", resdata)
	fmt.Printf("expected:%x\n", ExpectedData)

	if !bytes.Equal(ExpectedData, resdata) {
		t.Errorf("Pfcp marshal failed")
	}
}

func EstblishSession() {
	//PFCP Session Establishment Request (50)
	data, _ := hex.DecodeString("2132013d000000000000000000000200003c0005000aca6102" +
		"0039000d0200000000000027100aca610200010078003800020001001d0004000000ff0002005" +
		"100140001000015000901000000010aca5e0100170036010000327065726d6974206f75742031" +
		"362066726f6d20616e79203530303020746f2061737369676e656420313032352d36353533350" +
		"07c000101005f000100006c000400000001006d00040000000100010035003800020002001d00" +
		"04000000ff000200130014000101005d00050601010101007c000101006c000400000002006d0" +
		"0040000000100030016006c000400000001002c00010200040005002a00010100030012006c00" +
		"0400000002002c00010c005800010100550005005800010100070020006d00040000000100190" +
		"00100001a000a00000000010000000001007c0001010071000101")
	// 总长 321=4+317
	fmt.Printf("%x\n", data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 1
	//Message Type: 50
	//Length: 317
	//Seid: 0x0000000000000000
	//SequenceNumber: 2
	if msg.Header.MessageType != 50 || msg.Header.Length != 317 ||
		msg.Header.SequenceNumber != 2 {
		fmt.Printf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.SessionEstablishmentRequest)
	if !ok {
		fmt.Printf("Pfcp body unmarshal failed")
	}
	//10.202.97.2
	//2019-04-30 01:47:13 +0000 UTC
	fmt.Println(net.IP(v.IE.NodeID.NodeIDvalue))
	fmt.Println(v.IE.CPFSEID.SEID)

	fmt.Println("------response------")
	// 响应编码
	res := &pfcpv1.Message{}

	//配置参数设置
	n4layer.UpfN4Layer.UpfIp = "10.202.94.2"
	Dispatch(nil, msg, res)
	// todo pfcp encode
	//设置SEID的值为测试值
	resTmp, ok := res.Body.(*pfcp.SessionEstablishmentResponse)
	if !ok {
		fmt.Printf("Pfcp body marshal failed")
	}
	resTmp.IE.UPFSEID.SEID = 0x0000000000004e20
	resdata, err := res.Marshal()
	if err != nil {
		fmt.Printf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("2133002b000000000000271000000200003c000500" +
		"0aca5e0200130001010039000d020000000000004e200aca5e02")
	fmt.Printf("result  :%x\n", resdata)
	fmt.Printf("expected:%x\n", ExpectedData)

	if !bytes.Equal(ExpectedData, resdata) {
		fmt.Printf("Pfcp marshal failed")
	}
}

// todo
//Message Type: PFCP Session Establishment Request (50)
// amf side

// Message Type: PFCP Session Modification Request (52)
// upf side
func TestPfcpUnmarshal52(t *testing.T) {
	//PFCP Session Modification Request (52)
	data, _ := hex.DecodeString("213400340000000000004e2000000300000a0024006c000400" +
		"000002002c000102000b0013002a0001000054000a0100000000010aca5e0b")
	// N4上下文创建
	EstblishSession()

	// 总长 56=4+52
	fmt.Printf("receive data(len:%d)：%x\n", len(data), data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 1
	//Message Type: 52
	//Length: 52
	//Seid: 0x0000000000004e20
	//SequenceNumber: 3
	if msg.Header.MessageType != 52 || msg.Header.Length != 52 ||
		msg.Header.SequenceNumber != 3 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.SessionModifyRequest)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	//Update FAR : [Grouped IE]
	//    IE Type: Update FAR (10)
	//    IE Length: 36
	//    FAR ID : Dynamic by CP 2
	//    Apply Action :
	//        IE Type: Apply Action (44)
	//        IE Length: 1
	//        Flags: 0x02, FORW (Forward)
	//    Update Forwarding Parameters : [Grouped IE]
	//        IE Type: Update Forwarding Parameters (11)
	//        IE Length: 19
	//        Destination Interface : Access
	//        Outer Header Creation :
	//            IE Type: Outer Header Creation (84)
	//            IE Length: 10
	//            Outer Header Creation Description: GTP-U/UDP/IPv4  (256)
	//            TEID: 0x00000001
	//            IPv4 Address: 10.202.94.11
	for _, item := range v.IE.UpdateFARs {
		fmt.Println(item.IETypeLength)
		fmt.Println(item.FARID.Value)
		fmt.Println(item.ApplyAction.Flag)
		fmt.Println(item.UpdateForwardingPara.DstInterface.Value)
		fmt.Println(item.UpdateForwardingPara.OuterHeaderCreation.TEID)
		fmt.Println(item.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr)
		//check
		if item.Type != 10 || item.Length != 36 ||
			item.FARID.Value != 2 ||
			item.ApplyAction.Flag != 2 ||
			item.UpdateForwardingPara.OuterHeaderCreation.TEID != 1 ||
			!item.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr.Equal(net.ParseIP("10.202.94.11")) {
			t.Errorf("Pfcp body unmarshal failed")
		}

	}

	fmt.Println("------response------")
	// 响应编码
	res := &pfcpv1.Message{}

	//配置参数设置
	n4layer.UpfN4Layer.UpfIp = "10.202.94.2"
	//n4会话创建的上下文IE是0
	msg.Header.SEID = 0

	Dispatch(nil, msg, res)
	// todo pfcp encode
	/*//设置SEID的值为测试值
	resTmp, ok := res.Body.(*pfcp.SessionEstablishmentResponse)
	if !ok {
		t.Errorf("Pfcp body marshal failed")
	}
	//resTmp.IE.UPFSEID.SEID = 0x0000000000004e20*/
	resdata, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("213500110000000000002710000003000013000101")
	fmt.Printf("result  :%x\n", resdata)
	fmt.Printf("expected:%x\n", ExpectedData)

	if !bytes.Equal(ExpectedData, resdata) {
		t.Errorf("Pfcp marshal failed")
	}
}

// Message Type: PFCP Session Deletion Request (54)
// upf side
func TestPfcpUnmarshal54(t *testing.T) {
	//PFCP Session Modification Request (52)
	data, _ := hex.DecodeString("2136000c0000000000004e2000000400")
	// N4上下文创建
	EstblishSession()

	// 总长 56=4+52
	fmt.Printf("receive data(len:%d)：%x\n", len(data), data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 1
	//Message Type: 52
	//Length: 52
	//Seid: 0x0000000000004e20
	//SequenceNumber: 3
	if msg.Header.MessageType != 54 || msg.Header.Length != 12 ||
		msg.Header.SequenceNumber != 4 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	_, ok := msg.Body.(*pfcp.SessionReleaseRequest)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}

	fmt.Println("------response------")
	// 响应编码
	res := &pfcpv1.Message{}

	//配置参数设置
	n4layer.UpfN4Layer.UpfIp = "10.202.94.2"
	//n4会话创建的上下文IE是0
	msg.Header.SEID = 0

	Dispatch(nil, msg, res)
	// todo pfcp encode
	resdata, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("213700110000000000002710000004000013000101")
	fmt.Printf("result  :%x\n", resdata)
	fmt.Printf("expected:%x\n", ExpectedData)

	if !bytes.Equal(ExpectedData, resdata) {
		t.Errorf("Pfcp marshal failed")
	}
}

// Message Type: PFCP Heartbeat Request (1)
// upf side
// receive request
func TestPfcpUnmarshal1(t *testing.T) {
	//PFCP Heartbeat Request (1)
	data, _ := hex.DecodeString("2001000c0000070000600004e07227a1")
	fmt.Printf("%x\n", data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 1
	//Length: 12
	//SequenceNumber: 7
	if msg.Header.MessageType != 1 || msg.Header.Length != 12 ||
		msg.Header.SequenceNumber != 7 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.HeartbeatRequest)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}

	//2019-04-30 01:47:13 +0000 UTC
	fmt.Println(v.IE.RecoveryTimeStamp.RecoveryTimeStamp.UTC())

	fmt.Println("------response------")

	res := &pfcpv1.Message{}

	Dispatch(nil, msg, res)
	// todo pfcp encode
	data, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("2002000c0000070000600004e07227a1")

	fmt.Printf("ExpectedData:%x\n", ExpectedData)
	fmt.Printf("result      :%x\n", data)

	if !bytes.Equal(ExpectedData, data) {
		t.Errorf("Pfcp marshal failed")
	}
}

// Message Type: PFCP Heartbeat Request (1)
// upf side
// send request
func TestPfcpUnmarshal1Send(t *testing.T) {
	//PFCP Heartbeat Request (1)
	ExpectedReqdata, _ := hex.DecodeString("2001000c0000010000600004e07227a1")
	//请求编码
	req := pfcpv1.Message{}
	request := &pfcp.HeartbeatRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Heartbeat_Request,
			Length:         0, // 编码后填充
			SequenceNumber: 1},
	}
	//add IE
	//2019-04-30 01:47:13 +0000 UTC
	request.IE = &pfcp.IERecoveryTimeStamp{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeRecoveryTimeStamp,
			Length: 4},
		RecoveryTimeStamp: time.Unix(1556588833, 0),
	}

	req.Header.Version = request.PfcpHeader.Version
	req.Header.MessageType = request.PfcpHeader.MessageType
	req.Header.SequenceNumber = request.PfcpHeader.SequenceNumber
	//编码后填充
	req.Header.Length = 0
	req.Body = request
	fmt.Println(req.String())
	fmt.Println(request.IE.RecoveryTimeStamp.RecoveryTimeStamp.UTC().String())
	// todo pfcp encode
	data, err := req.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal err %s", err)
	}
	fmt.Printf("Expected:%x\n", ExpectedReqdata)
	fmt.Printf("Result  :%x\n", data)
	if !bytes.Equal(data, ExpectedReqdata) {
		t.Errorf("Pfcp msg marshal failed")
	}
	fmt.Println("------response------")
	// 响应解码
	//Message Type: PFCP Heartbeat Response (2)
	resdata, _ := hex.DecodeString("2002000c0000010000600004e07227a1")
	fmt.Printf("resdata:%x\n", resdata)
	msg := pfcpv1.Message{}
	msg.Unmarshal(resdata)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 2
	//Length: 12
	//SequenceNumber: 1
	if msg.Header.MessageType != 2 || msg.Header.Length != 12 ||
		msg.Header.SequenceNumber != 1 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.HeartbeatResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	// 消息头填充
	v.PfcpHeader.Version = msg.Header.Version
	v.PfcpHeader.MessageType = msg.Header.MessageType
	v.PfcpHeader.Length = msg.Header.Length
	v.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber

	//2019-04-30 01:47:13 +0000 UTC
	fmt.Println(v.IE.RecoveryTimeStamp.UTC())

	err = Dispatch(nil, msg, nil)
	if err != nil {
		t.Errorf("Pfcp msg handler err %s", err)
	}

	if v.PfcpHeader.Length != 12 ||
		v.PfcpHeader.MessageType != 2 ||
		v.PfcpHeader.SequenceNumber != 1 ||
		v.IE.RecoveryTimeStamp.UTC().String() != "2019-04-30 01:47:13 +0000 UTC" {
		t.Errorf("Pfcp header unmarshal failed")
	}
}

// Message Type: PFCP Association Update Request (7)
// upf side
// send request
func TestPfcpUnmarshal7(t *testing.T) {
	//PFCP Association Update Request (7)
	ExpectedReqdata, _ := hex.DecodeString("2007001200000300003c0005000aca5e02006f000101")
	//请求编码
	req := pfcpv1.Message{}
	request := &pfcp.PFCPAssociationUpdateRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Association_Update_Request,
			Length:         0, // todo 编码后填充
			SequenceNumber: 3},
	}
	request.IE = &pfcp.IEPFCPAssociationUpdateRequest{}
	request.IE.NodeID = &pfcp.IENodeID{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeNodeID,
			Length: 5,
		},
		NodeIDType:  0,
		NodeIDvalue: []byte{10, 202, 94, 2}, // upf ip
	}

	request.IE.PFCPAssociationReleaseRequest = &pfcp.IEPFCPAssociationReleaseRequest{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeIEPFCPAssociationReleaseRequest,
			Length: 1,
		},
		SARR: true,
	}

	request.IE.IeFlags.Set(pfcp.IeTypeIEPFCPAssociationReleaseRequest)

	req.Header.Version = request.PfcpHeader.Version
	req.Header.MessageType = request.PfcpHeader.MessageType
	req.Header.SequenceNumber = request.PfcpHeader.SequenceNumber
	//todo 编码后填充
	req.Header.Length = 0
	req.Body = request
	fmt.Println(req.String())

	// todo pfcp encode
	data, err := req.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal err %s", err)
	}
	fmt.Printf("%x\n", ExpectedReqdata)
	fmt.Printf("%x\n", data)
	if !bytes.Equal(data, ExpectedReqdata) {
		t.Errorf("Pfcp msg marshal failed")
	}
	fmt.Println("------response------")
	// 响应解码
	resdata, _ := hex.DecodeString("2008001200000300003c0005000aca61020013000101")
	fmt.Printf("resdata:%x\n", resdata)
	msg := pfcpv1.Message{}
	msg.Unmarshal(resdata)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 8
	//Length: 18
	//SequenceNumber: 3
	if msg.Header.MessageType != 8 || msg.Header.Length != 18 ||
		msg.Header.SequenceNumber != 3 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.PFCPAssociationUpdateResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	// 消息头填充
	v.PfcpHeader.Version = msg.Header.Version
	v.PfcpHeader.MessageType = msg.Header.MessageType
	v.PfcpHeader.Length = msg.Header.Length
	v.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber

	// 10.202.97.2 //smf ip
	fmt.Println(net.IP(v.IE.NodeID.NodeIDvalue))
	fmt.Println((v.IE.Cause.CauseValue))
	//fmt.Println(v.IE.RecoveryTimeStamp.RecoveryTimeStamp.UTC())

	err = Dispatch(nil, msg, nil)
	if err != nil {
		t.Errorf("Pfcp msg handler err %s", err)
	}
	// upf ip
	if net.IP(v.IE.NodeID.NodeIDvalue).String() != "10.202.97.2" ||
		v.IE.Cause.CauseValue != 1 {
		t.Errorf("Pfcp header unmarshal failed")
	}
}

// Message Type: PFCP Association Release Request (9)
// upf side
func TestPfcpUnmarshal9(t *testing.T) {
	//PFCP Association Release Request (9)
	data, _ := hex.DecodeString("2009000d00000f00003c0005000aca6102")
	fmt.Printf("%x\n", data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 9
	//Length: 13
	//SequenceNumber: 15
	if msg.Header.MessageType != 9 || msg.Header.Length != 13 ||
		msg.Header.SequenceNumber != 15 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.PFCPAssociationReleaseRequest)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	//10.202.97.2
	fmt.Println(net.IP(v.IE.NodeID.NodeIDvalue))

	fmt.Println("------response------")

	res := &pfcpv1.Message{}

	Dispatch(nil, msg, res)

	//设置测试参数
	response, ok := res.Body.(*pfcp.PFCPAssociationReleaseResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	response.IE.NodeID.NodeIDvalue = []byte{10, 202, 94, 2}

	// todo pfcp encode
	data, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("200a001200000f00003c0005000aca5e020013000101")

	fmt.Printf("ExpectedData:%x\n", ExpectedData)
	fmt.Printf("Result      :%x\n", data)

	if !bytes.Equal(ExpectedData, data) {
		t.Errorf("Pfcp marshal failed")
	}
}

// Message Type: PFCP Session Report Request (56)
// upf side
// send request
func TestPfcpUnmarshal56Send(t *testing.T) {
	//PFCP Session Report Request (56)
	ExpectedReqdata, _ := hex.DecodeString("2138001b000000000000271000000200002700010100530006003800020002")
	//请求编码
	req := pfcpv1.Message{}
	request := &pfcp.SessionReportRequest{
		PfcpHeader: pfcp.PfcpHeaderforSession{
			Version:        pfcp.Version,
			SFlag:          1,
			MessageType:    pfcp.PFCP_Session_Report_Request,
			Length:         0, // 编码后填充
			SEID:           10000,
			SequenceNumber: 2},
	}
	//add IE
	//Report Type
	request.IE.ReportType.Type = pfcp.IeTypeReportType
	request.IE.ReportType.Length = 0 // Fill after encoding
	request.IE.ReportType.DLDR = true

	//set optional IE
	request.IE.IeFlags.Set(pfcp.IeTypeDownlinkDataReport)
	request.IE.DownlinkDataReport = &pfcp.IEDownlinkDataReport{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeDownlinkDataReport,
			Length: 0},
		PDRID: pfcp.IEPDRID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypePacketDetectionRuleID,
				Length: 0},
			RuleID: 2,
		},
	}

	req.Header.Version = request.PfcpHeader.Version
	req.Header.SFlag = request.PfcpHeader.SFlag
	req.Header.MessageType = request.PfcpHeader.MessageType
	req.Header.SEID = request.PfcpHeader.SEID
	req.Header.SequenceNumber = request.PfcpHeader.SequenceNumber
	//编码后填充
	req.Header.Length = 0
	req.Body = request
	fmt.Println(req.String())
	// todo pfcp encode
	data, err := req.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal err %s", err)
	}
	fmt.Printf("Expected:%x\n", ExpectedReqdata)
	fmt.Printf("Result  :%x\n", data)
	if !bytes.Equal(data, ExpectedReqdata) {
		t.Errorf("Pfcp msg marshal failed")
	}
	fmt.Println("------response------")
	// 响应解码
	//Message Type: PFCP Session Report Response (57)
	resdata, _ := hex.DecodeString("213900110000000000004e20000002000013000101")
	fmt.Printf("resdata:%x\n", resdata)
	msg := pfcpv1.Message{}
	msg.Unmarshal(resdata)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 1
	//Message Type: 57
	//Length: 17
	//SEID: 20000
	//SequenceNumber: 2
	if msg.Header.MessageType != 57 || msg.Header.Length != 17 ||
		msg.Header.SEID != 20000 ||
		msg.Header.SequenceNumber != 2 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.SessionReportResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	// 消息头填充
	v.PfcpHeader.Version = msg.Header.Version
	v.PfcpHeader.SFlag = msg.Header.SFlag
	v.PfcpHeader.MessageType = msg.Header.MessageType
	v.PfcpHeader.Length = msg.Header.Length
	v.PfcpHeader.SEID = msg.Header.SEID
	v.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber

	err = Dispatch(nil, msg, nil)
	if err != nil {
		t.Errorf("Pfcp msg handler err %s", err)
	}

	if v.PfcpHeader.Length != 17 ||
		v.PfcpHeader.MessageType != 57 ||
		v.PfcpHeader.SequenceNumber != 2 ||
		v.IE.Cause.CauseValue != 1 {
		t.Errorf("Pfcp header unmarshal failed")
	}
}

// PFCP_Version_Not_Supported_Response = 11
// upf side
// receive response test,send response test
func TestPfcpUnmarshal11(t *testing.T) {
	//PFCP Version Not Supported Response (11)
	data, _ := hex.DecodeString("200b000400000700")
	fmt.Printf("%x\n", data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)
	//
	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 11
	//Length: 4
	//SequenceNumber: 7
	if msg.Header.MessageType != 11 || msg.Header.Length != 4 ||
		msg.Header.SequenceNumber != 7 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	_, ok := msg.Body.(*pfcp.PFCPVersionNotSupportedResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}

	fmt.Println("------response------")

	res := &pfcpv1.Message{}
	// 发送 version not support response 11
	//pfcphandler.Dispatch(msg, res)
	res.Header.Version = 1
	res.Header.MessageType = pfcp.PFCP_Version_Not_Supported_Response
	res.Header.Length = 0
	res.Header.SequenceNumber = 7

	request := &pfcp.PFCPVersionNotSupportedResponse{}
	res.Body = request
	data, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("200b000400000700")

	fmt.Printf("ExpectedData:%x\n", ExpectedData)
	fmt.Printf("result      :%x\n", data)

	if !bytes.Equal(ExpectedData, data) {
		t.Errorf("Pfcp marshal failed")
	}
}

// PFCP Node Report Request = 12
// upf side
// upf -- smf
// PFCP Node Report Response = 13
func TestPfcpUnmarshal12(t *testing.T) {
	//PFCP Node Report Request (12)
	ExpectedReqdata, _ := hex.DecodeString("200c001f00000200003c0005000aca5e0200650001010066000900670005020aca6402")
	//请求编码
	req := pfcpv1.Message{}
	request := &pfcp.PFCPNodeReportRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Node_Report_Request,
			Length:         0, // 编码后填充
			SequenceNumber: 2},
	}
	//add IE
	//Report Type
	request.IE = &pfcp.IEPFCPNodeReportRequest{}
	request.IE.NodeID = &pfcp.IENodeID{}
	request.IE.NodeID.Type = pfcp.IeTypeNodeID
	request.IE.NodeID.Length = 0                                     // Fill after encoding
	request.IE.NodeID.NodeIDType = 0                                 // ipv4
	request.IE.NodeID.NodeIDvalue = net.ParseIP("10.202.94.2").To4() // ipv4

	request.IE.NodeReportType = &pfcp.IENodeReportType{}
	request.IE.NodeReportType.Type = pfcp.IeTypeNodeReportType
	request.IE.NodeReportType.Length = 0
	request.IE.NodeReportType.UPFR = true
	//set optional IE
	request.IE.IeFlags.Set(pfcp.IeTypeUserPlanePathFailureReport)
	request.IE.UserPlanePathFailureReport = &pfcp.IEUserPlanePathFailureReport{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeUserPlanePathFailureReport,
			Length: 0},
		RemoteGTPUPeer: &pfcp.IERemoteGTPUPeer{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeRemoteGtpuPeer,
				Length: 0},
			V4:          true,
			IPv4address: net.ParseIP("10.202.100.2").To4(), //gnb addr
		},
	}

	req.Header.Version = request.PfcpHeader.Version
	req.Header.MessageType = request.PfcpHeader.MessageType
	req.Header.SequenceNumber = request.PfcpHeader.SequenceNumber
	//编码后填充
	req.Header.Length = 0
	req.Body = request
	fmt.Println(req.String())
	// todo pfcp encode
	data, err := req.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal err %s", err)
	}
	fmt.Printf("Expected:%x\n", ExpectedReqdata)
	fmt.Printf("Result  :%x\n", data)
	if !bytes.Equal(data, ExpectedReqdata) {
		t.Errorf("Pfcp msg marshal failed")
	}
	fmt.Println("------response------")
	// 响应解码
	//Message Type: PFCP Node Report Response (13)
	resdata, _ := hex.DecodeString("200d001200000200003c0005000aca61020013000101")
	fmt.Printf("resdata:%x\n", resdata)
	msg := pfcpv1.Message{}
	msg.Unmarshal(resdata)

	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 13
	//Length: 18
	//SequenceNumber: 2
	if msg.Header.MessageType != 13 || msg.Header.Length != 18 ||
		msg.Header.SequenceNumber != 2 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	v, ok := msg.Body.(*pfcp.PFCPNodeReportResponse)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	// 消息头填充
	v.PfcpHeader.Version = msg.Header.Version
	v.PfcpHeader.MessageType = msg.Header.MessageType
	v.PfcpHeader.Length = msg.Header.Length
	v.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber

	err = Dispatch(nil, msg, nil)
	if err != nil {
		t.Errorf("Pfcp msg handler err %s", err)
	}

	if v.PfcpHeader.Length != 18 ||
		v.PfcpHeader.MessageType != 13 ||
		v.PfcpHeader.SequenceNumber != 2 ||
		v.IE.Cause.CauseValue != 1 {
		t.Errorf("Pfcp header unmarshal failed")
	}
}

// PFCP PFD Management Request(3)
// upf side
// smf -- upf
// PFCP PFD Management Response(4)
func TestPfcpUnmarshal3(t *testing.T) {
	//PFCP PFD Management Request(3)
	data, _ := hex.DecodeString("2003002100000200003a00190018000461707031003b000d003d000901000005666c6f7731")
	fmt.Printf("%x\n", data)
	msg := pfcpv1.Message{}
	msg.Unmarshal(data)
	//
	fmt.Println(msg.String())
	//Version: 1
	//MP: 0
	//S: 0
	//Message Type: 3
	//Length: 33
	//SequenceNumber: 2
	if msg.Header.MessageType != 3 || msg.Header.Length != 33 ||
		msg.Header.SequenceNumber != 2 {
		t.Errorf("Pfcp header unmarshal failed")
	}

	req, ok := msg.Body.(*pfcp.PFCPPFDManagementRequest)
	if !ok {
		t.Errorf("Pfcp body unmarshal failed")
	}
	appStr := string(req.IE.ApplicationIDsPFDs.ApplicationID.ApplicationIdentifier)
	flowStr := req.IE.ApplicationIDsPFDs.PFD.PFDContexts.FlowDescription
	fmt.Println(appStr)
	fmt.Println(flowStr)
	if appStr != "app1" || flowStr != "flow1" {
		t.Errorf("Pfcp body unmarshal failed")
	}

	fmt.Println("------response------")

	res := &pfcpv1.Message{}
	// send PFCP Node Report Response(4)
	Dispatch(nil, msg, res)

	data, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("20040009000002000013000101")

	fmt.Printf("ExpectedData:%x\n", ExpectedData)
	fmt.Printf("result      :%x\n", data)

	if !bytes.Equal(ExpectedData, data) {
		t.Errorf("Pfcp marshal failed")
	}
}

// PFCP PFD Management Request(3)
func TestPfcpUnmarshal(t *testing.T) {
	////PFCP PFD Management Request(3)
	ExpectedReqdata, _ := hex.DecodeString("2003002100000200003a00190018000461707031003b000d003d000901000005666c6f7731")
	//请求编码
	req := pfcpv1.Message{}
	request := &pfcp.PFCPPFDManagementRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_PFD_Management_Request,
			Length:         0, // 编码后填充
			SequenceNumber: 2},
	}
	//add IE
	//Report Type
	request.IE = &pfcp.IEPFCPPFDManagementRequest{}
	request.IE.ApplicationIDsPFDs = &pfcp.IEApplicationIDsPFDs{}
	request.IE.ApplicationIDsPFDs.Type = pfcp.IeTypeApplicationIDsPFDs // 在编码中填写，此处可以不用填写
	request.IE.ApplicationIDsPFDs.Length = 0                           // filling after encoding

	request.IE.ApplicationIDsPFDs.ApplicationID = &pfcp.IEApplicationID{} // ipv4
	request.IE.ApplicationIDsPFDs.ApplicationID.ApplicationIdentifier = []byte("app1")

	request.IE.ApplicationIDsPFDs.IeFlags.Set(pfcp.IeTypePFDcontext)
	request.IE.ApplicationIDsPFDs.PFD = &pfcp.IEPFDContext{}
	request.IE.ApplicationIDsPFDs.PFD.PFDContexts = &pfcp.IEPFDContents{}
	request.IE.ApplicationIDsPFDs.PFD.PFDContexts.FD = true
	request.IE.ApplicationIDsPFDs.PFD.PFDContexts.LengthofFlowDes = 5
	request.IE.ApplicationIDsPFDs.PFD.PFDContexts.FlowDescription = "flow1"

	req.Header.Version = request.PfcpHeader.Version
	req.Header.MessageType = request.PfcpHeader.MessageType
	req.Header.SequenceNumber = request.PfcpHeader.SequenceNumber
	//编码后填充
	req.Header.Length = 0
	req.Body = request
	fmt.Println(req.String())
	// todo pfcp encode
	data, err := req.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal err %s", err)
	}
	fmt.Printf("Expected:%x\n", ExpectedReqdata)
	fmt.Printf("Result  :%x\n", data)
	if !bytes.Equal(data, ExpectedReqdata) {
		t.Errorf("Pfcp msg marshal failed")
	}
}
