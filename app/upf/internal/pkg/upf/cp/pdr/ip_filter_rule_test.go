package pdr

import (
	"container/list"
	"encoding/json"
	"fmt"
	"lite5gc/cmn/message/pfcp"
	"lite5gc/cmn/nas/nasie"
	"regexp"
	"runtime/debug"
	"testing"
)

func TestIpFilterRuleCodec(t *testing.T) {

	var ipRule IPFilterRule
	ipRule.Action = "permit"
	ipRule.Direction = "out"
	ipRule.Protocol = "ip"
	ipRule.SourceIP = "192.0.2.10/24"
	ipRule.DestinationIP = "192.0.2.20/24"
	ipRule.SourcePort = "5000"
	ipRule.DestinationPort = "6000-8000"

	// 编码
	ruleStr, err := json.Marshal(ipRule)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(ruleStr))
	//	output
	//	{"action":"permit","dir":"out","proto":"ip","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24","src_port":"5000","dst_port":"6000-8000"}
	if string(ruleStr) != `{"action":"permit","dir":"out","proto":"ip","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24","src_port":"5000","dst_port":"6000-8000"}` {
		t.Errorf("Failed to encode ")
	}
	// 解码
	var dstRule IPFilterRule
	Str := []byte(`{"action":"permit","dir":"out","proto":"6","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24","src_port":"5000","dst_port":"6000-8000"}`)
	err = json.Unmarshal(Str, &dstRule)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v\n", ipRule)
	fmt.Printf("%v\n", dstRule)
	/*{"action":"permit","dir":"out","proto":"ip","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24","src_port":"5000","dst_port":"6000-8000"}
	{permit out ip 192.0.2.10/24 192.0.2.20/24 5000 6000-8000    }
	{permit out ip 192.0.2.10/24 192.0.2.20/24 5000 6000-8000    }*/

	fmt.Println(ParsePortRange(ipRule.SourcePort))
	fmt.Println(ParsePortRange(ipRule.DestinationPort))
	fmt.Println(ParsePortRange("8000-6000"))
	fmt.Println(ParsePortRange(""))
	/*{5000 5000}
	{6000 8000}
	{6000 8000}
	{0 0}*/

	filter := &IpPacketFilterSetTmp{}
	//upd 17 、tcp 6 、icmp 1
	fmt.Println("input:", string(Str))
	FlowDescriptionParse(filter, Str)
	fmt.Println("output:", *filter)
	//	output: {{192.0.2.0 ffffff00} {5000 5000} {192.0.2.0 ffffff00} {6000 8000} 6 0 0 0 0}
	fmt.Println()
	filterB := &IpPacketFilterSetTmp{}
	StrB := []byte(`{"action":"permit","dst_ip":"192.0.2.20/32","src_port":"5000"}`)
	fmt.Println("input:", string(StrB))
	FlowDescriptionParse(filterB, StrB)
	test := fmt.Sprintf("%v", *filterB)
	output := "{{<nil> <nil>} 5000 {192.0.2.20 ffffffff} 0  0 0 0 0}"
	fmt.Printf("output:%s\n", output)
	if test != output {
		t.Errorf("Failed to encode ")
	}
}

type testItem struct {
	input  interface{}
	output interface{}
}

// "in" 上行消息  src_ip是UE的IP
// "out" 下行消息 dst_ip是UE的IP
var OrderlyPDRs = []testItem{ // "out" 是外部发给UE的，“in”是UE发出的
	testItem{input: []byte(`{"action":"permit","dir":"out","proto":"ip","src_ip":"192.0.2.10/32","dst_ip":"192.0.2.20/0","src_port":"0","dst_port":"6000-8000"}`),
		output: int(5)},
	testItem{input: []byte(`{"action":"permit","dir":"in","proto":"ip","dst_ip":"192.0.2.20/0","src_port":"5000","dst_port":"6000-8000"}`),
		output: int(4)},
	testItem{input: []byte(`{"action":"permit","dir":"in","proto":"17","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24","src_port":"5000","dst_port":"6000-8000"}`),
		output: int(6)},
	testItem{input: []byte(`{"action":"permit","dir":"in","proto":"ip","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24"}`),
		output: int(3)},
}

func TestOrderlyPDRsPrint(t *testing.T) {
	for _, item := range OrderlyPDRs {
		filterB := &IpPacketFilterSetTmp{}
		StrB := item.input.([]byte)
		fmt.Println("input:", string(StrB))
		FlowDescriptionParse(filterB, StrB)
		fmt.Printf("output:%v\n", *filterB)

		PacketDetectionRule := PacketDetectionRule{}
		PacketDetectionRule.PDI.PacketFilterSet.IpPacketFilterSet = []IpPacketFilterSetTmp{*filterB}
		pdr := PDRListElement{Pdr: &PacketDetectionRule}
		PDRFields := MappingPDRtoMatchField(pdr)

		pdrs := &OrderlyFieldNumPDRs{}
		pdrs.pdrList = list.New()
		pdrs.pdrList.PushBack(PDRFields)
		OrderlyPDRsPrint(pdrs)
		if pdrs.pdrList.Len() != 1 {
			t.Errorf("Failed to Mapping PDR ")
		}
		if PDRFields.Count != item.output.(int) {
			t.Errorf("Error in number of mapping fields,expected output:%d,result:%d", item.output.(int), PDRFields.Count)
		}
	}

	//StrB := []byte(`{"action":"permit","dir":"in","proto":"ip","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24","src_port":"5000","dst_port":"6000-8000"}`)

}

func TestNilAddr(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("work failed:", err)
			debug.PrintStack()
		}
	}()
	var OuterHeaderDesc uint16
	OuterHeaderDesc = pfcp.IEOuterHCreation_GTPU_UDP_IPv4
	fmt.Println(OuterHeaderDesc)

	listA := make([]byte, 100)
	fmt.Println(listA[0])

	a := PacketDetectionRule{}
	if a.FarI.Far == nil {
		fmt.Println("Ok")
	}
	if a.FarI.Far != nil && a.FarI.Far.OuterHeaderCreation != nil {
		fmt.Println("Ok")
	}
	if a.FarI.Far.OuterHeaderCreation != nil && a.FarI.Far != nil {
		fmt.Println("Ok")
	}

}

func TestMatchingPDRPrint(t *testing.T) {
	pdr := &MatchPDR{}
	Tuple := &IpPacketHeaderFields{}
	teid := &TEIdN4SessionValue{}
	MatchingPDRPrint(pdr, Tuple, teid)
}

func TestIPFilterRule_DecodeStd(t *testing.T) {
	sdf := []byte("permit out ip from 192.0.2.10/24 5000 to 192.0.2.20/24 6000-8000")
	sdf1 := []byte(" permit out   17 from any   5000 To    assigned ")
	sdf3 := []byte(" permit out   6 from any   to     ")
	sdf2 := []byte(`{"action":"permit","dir":"out","proto":"ip","src_ip":"192.0.2.10/32","dst_ip":"192.0.2.20/0","src_port":"0","dst_port":"6000-8000"}`)
	var dstRule IPFilterRule
	dstRule.DecodeStd(sdf)
	fmt.Printf("%+v\n", dstRule)
	dstRule = IPFilterRule{}
	dstRule.DecodeStd(sdf1)
	fmt.Printf("%+v\n", dstRule)
	dstRule = IPFilterRule{}
	dstRule.DecodeStd(sdf2)
	fmt.Printf("%+v\n", dstRule)

	dstRule = IPFilterRule{}
	dstRule.DecodeStd(sdf3)
	fmt.Printf("%+v\n", dstRule)

	//output
	//	{Action:permit Direction:out Protocol:ip SourceIP:192.0.2.10/24 DestinationIP:192.0.2.20/24 SourcePort:5000 DestinationPort:6000-8000 TCPFlags: IPFragmentFlag: IPOptions: ICMPTypes:}
	//{Action:permit Direction:out Protocol:17 SourceIP:0.0.0.0/0 DestinationIP:0.0.0.0/0 SourcePort:5000 DestinationPort: TCPFlags: IPFragmentFlag: IPOptions: ICMPTypes:}
	//{Action:permit Direction:out Protocol:ip SourceIP: DestinationIP: SourcePort: DestinationPort: TCPFlags: IPFragmentFlag: IPOptions: ICMPTypes:}
	//{Action:permit Direction:out Protocol:ip SourceIP: DestinationIP: SourcePort: DestinationPort: TCPFlags: IPFragmentFlag: IPOptions: ICMPTypes:}
}

func TestIpFilterRuleCodecStd(t *testing.T) {

	// 解码
	Str := []byte("permit out ip from any 5000 to 192.0.2.20/24 6000-8000")
	var validSdf = regexp.MustCompile(`^[ ]*(permit|deny)[ ]+(out|in)[ ]+(.+)[ ]from[ ]+(.+)[ ]to[ ]+(.*)$`)
	fmt.Println(validSdf.MatchString(string(Str)))
	fmt.Println(validSdf.FindString(string(Str)))

	filter := &IpPacketFilterSetTmp{}
	//upd 17 、tcp 6 、icmp 1
	fmt.Println("input:", string(Str))
	FlowDescriptionParse(filter, Str)
	fmt.Println("out output:", *filter)
	filter.Direction = nasie.UplinkOnly
	if filter.Direction == nasie.UplinkOnly {
		filter.SrcIp, filter.DstIp = filter.DstIp, filter.SrcIp
		filter.SrcPort, filter.DstPort = filter.DstPort, filter.SrcPort
	}
	fmt.Println("in output:", *filter)
	//	output: {{192.0.2.0 ffffff00} {5000 5000} {192.0.2.0 ffffff00} {6000 8000} 6 0 0 0 0}
	fmt.Println()

	test := fmt.Sprintf("%v", *filter)
	output := "{{192.0.2.0 ffffff00} 6000-8000 {0.0.0.0 00000000} 5000 ip 0 0 0 2}"
	fmt.Printf("output:%s\n", output)
	if test != output {
		t.Errorf("Failed to encode ")
	}
}
