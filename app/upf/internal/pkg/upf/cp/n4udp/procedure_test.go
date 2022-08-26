package n4udp_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"upf/internal/pkg/cmn/message/pfcp"
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
	"upf/internal/pkg/upf/cp/n4layer"
	. "upf/internal/pkg/upf/cp/n4udp"
)

// Message Type: PFCP Session Establishment Request (50)
// upf side
func TestPfcpSessionEstablishment(t *testing.T) {
	//PFCP Session Establishment Request (50)
	data, _ := hex.DecodeString("21320157000000000000000000000200003c000500ac100105" +
		"0039000d020000000000002710ac10010500010068003800020001001d0004000000ff0002004" +
		"100140001000015000901001e8480ac10011000170026010000227065726d6974206f75742069" +
		"702066726f6d20616e7920746f2061737369676e6564007c000101005f000100006c000400000" +
		"001006d0004000000010001005f003800020002001d0004000000ff0002003d0014000101005d" +
		"0005060a37000000170026010000227065726d6974206f75742069702066726f6d20616e79207" +
		"46f2061737369676e6564007c000101006c000400000002006d00040000000100030016006c00" +
		"0400000001002c00010200040005002a00010100030012006c000400000002002c00010c00580" +
		"0010100550005005800010100070020006d0004000000010019000100001a000a00000003e800" +
		"0000fa00007c0001010071000101")
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
	if msg.Header.MessageType != 50 || msg.Header.Length != 343 ||
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
	n4layer.UpfN4Layer.UpfIp = "172.16.1.16"
	Dispatch(nil, msg, res)
	// todo pfcp encode
	//设置SEID的值为测试值
	_, ok = res.Body.(*pfcp.SessionEstablishmentResponse)
	if !ok {
		t.Errorf("Pfcp body marshal failed")
	}
	//resTmp.IE.UPFSEID.SEID = 0x0000000000004e20
	resdata, err := res.Marshal()
	if err != nil {
		t.Errorf("Pfcp msg marshal failed")
	}
	ExpectedData, _ := hex.DecodeString("2133002b000000000000271000000200003c000500" +
		"ac10011000130001010039000d020000000000000000ac100110")
	//21330023000000000000271000000200003c000100001300010100390009020000000000000000
	fmt.Printf("result  :%x\n", resdata)
	fmt.Printf("expected:%x\n", ExpectedData)

	if !bytes.Equal(ExpectedData, resdata) {
		t.Errorf("Pfcp marshal failed")
	}
}
