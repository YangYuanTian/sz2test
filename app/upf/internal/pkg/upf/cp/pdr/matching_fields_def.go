package pdr

import (
	"container/list"
	"fmt"
	"net"
	"upf/internal/pkg/cmn/nas/nasie"
	"upf/internal/pkg/cmn/syncmap"
	"upf/internal/pkg/cmn/types3gpp"
)

// 3GPP TS 23.501 V15.3.0 (2018-09)
// 5.7	QoS model
//Preprocessing of Packet Matching Fields
// 预先构造有序的pdrs结构，使用时直接匹配

// PDR中的检测字段 destination field
type IpPacketDstFields struct {
	// todo:没有使用
	SrcIp                  net.IP
	SrcPort                int
	DstIp                  net.IP
	DstPort                int
	Protocol               byte
	ToSTrafficClass        uint16 // ipv4 TOS //ipv6 Traffic class
	FlowLabel              uint32 // ipv6
	SecurityParameterIndex uint32 //types3gpp.SecurityIndication
	Direction              nasie.PacketFilterDirection
}

// 获取的五元组信息
type IpPacketHeaderFields struct {
	SrcIp     net.IP
	SrcPort   int
	DstIp     net.IP
	DstPort   int
	Protocol  byte
	Direction nasie.PacketFilterDirection
	//ip total length
	Length uint16
}

// 五元组转换为对应的PDR中的检测字段 source field
type IpPacketSrcFields struct {
	SrcIp                  net.IP
	SrcPort                int
	DstIp                  net.IP
	DstPort                int
	Protocol               byte
	ToSTrafficClass        uint16 // ipv4 TOS //ipv6 Traffic class
	FlowLabel              uint32 // ipv6
	SecurityParameterIndex uint32 //types3gpp.SecurityIndication
	Direction              nasie.PacketFilterDirection
}

// dst 匹配字段集合构造
type MatchField struct {
	NameIndex NameIndex
	value     interface{} // NameIndex 决定其类型
}

// 构造目的集合--一个PDR的字段集合
type MatchFieldsList []MatchField

// 构造用于排序的PDR结构
type PDRFields struct {
	Fields []MatchField
	//Precedence
	Precedence uint32
	// Field Number Statistics, 用于排序
	Count int
	Pdr   *PacketDetectionRule
}

// 匹配结果
type MatchPDR struct {
	FieldSet []MatchField      // dst field
	SrcField IpPacketSrcFields // src field
	Result   bool
	Pdr      *PacketDetectionRule
}

type NameIndex byte

const (
	NameIndex_default NameIndex = 0 // 不比较
	// IP five tuple
	NameIndex_SrcIP    NameIndex = 1
	NameIndex_SrcPort  NameIndex = 2
	NameIndex_DstIp    NameIndex = 3
	NameIndex_DstPort  NameIndex = 4
	NameIndex_Protocol NameIndex = 5
	// option
	NameIndex_ToSTrafficClass        NameIndex = 6
	NameIndex_FlowLabel              NameIndex = 7
	NameIndex_SecurityParameterIndex NameIndex = 8
	NameIndex_Direction              NameIndex = 9

	NameIndex_max NameIndex = 10
)

// 1、优先级；2、优先级相同时，字段数多在前
// PDRs 构造，优先级有序，高到低
// 构造时使用
type OrderlyPrecedencePDR PDRConfList //MatchPDR
// 如果优先级相同，使用字段数排序，字段数多排在前，（降序）
type OrderlyFieldNumPDRTmp struct {
	//todo
	PdrsList []MatchFieldsList
}

// PDRs 构造，字段数有序，多到少。同等条件原则是匹配第一个，即成功匹配
// PDRs 排序后的结果
type OrderlyFieldNumPDRs struct {
	pdrList *list.List //元素是PDRFields
}

// 5个检测字段的匹配规则
/*
1、多字段完全匹配
2、模糊匹配
*/
// 1、多字段完全匹配，Exact matching
// 相同字段，值相等
func ExactMatching() {
	//nasie.MatchAlltype
}

// 2、模糊匹配
/*Fuzzy matching：Wildcard matching，Mask matching*/
func FuzzyMatching() {

}

// 数据包匹配规则，使用二层表匹配
/*
1、根据UE IP匹配N4会话
2、从N4会话 PDR 匹配五元组
3、匹配到的PDR对当前五元组是可以复用的。可以存储于UEIpMatchingN4Session表中
*/

// 1、根据UE IP匹配N4会话,构造UEIpMatchingN4Session表
// N4 会话匹配表
type UEIpN4SessionValue struct {
	//  key
	UeIp string
	//	value
	SEID uint64    // N4SessionPDRContextTable key
	Pdr  *MatchPDR //PacketDetectionRule // 记录上次匹配的规则
}
type UEIpMatchingN4SessionTable struct {
	//  key
	//UeIp string
	////	value
	//SEID uint64 // N4SessionPDRContextTable key
	//Pdr *MatchPDR
	syncmap.SyncMap
}

// N4 会话匹配表
type TEIdN4SessionValue struct {
	//  key
	TEID uint32
	//	value
	SEID uint64    // N4SessionPDRContextTable key
	Pdr  *MatchPDR //PacketDetectionRule // 记录上次匹配的规则
}

// 根据TEID匹配N4会话,构造TEIdMatchingN4N4SessionTable表
type TEIdMatchingN4N4SessionTable struct {
	//  key
	//TEID uint32
	////	value
	//SEID uint64 // N4SessionPDRContextTable key
	//Pdr *MatchPDR
	syncmap.SyncMap
}

// DNN IP 表
type DnnIPTable struct {
	// key: DNN string
	// value: DnnGwIp []byte//[4byte]
	syncmap.SyncMap
}

// 2、五元组与N4会话匹配，构造
// SEID 查表 var seidUpfN4CxtTable syncmap.SyncMap //key:seid,value:N4Cxt
type N4SessionPDRsOrderlyTable struct {
	//SEID uint64        // key
	//OrderlyFieldNumPDRs // value
	syncmap.SyncMap
}

// UPF上保存的PDR配置列表
type PDRConfList struct {
	PdrList     []PDRListElement
	UpfTEID     types3gpp.Teid
	UpfTEID_N9  types3gpp.Teid
	UEIPAddress net.IP
} //[]PacketDetectionRule
func (l *PDRConfList) String() string {
	//PdrList.String()
	s := fmt.Sprintf("UpfTEID:%d,UEIPAddress:%s\n", l.UpfTEID, l.UEIPAddress)
	for i, v := range l.PdrList {
		s += fmt.Sprintf("pdr list:%d,%s", i, v.Pdr)
	}
	return s
}

type PDRListElement struct {
	//precedence uint32
	Pdr *PacketDetectionRule
}

// 优先级升序，1是高优先级，255是低优先级
func (l PDRConfList) Len() int { return len(l.PdrList) }
func (l PDRConfList) Less(i, j int) bool {
	return l.PdrList[i].Pdr.Precedence < l.PdrList[j].Pdr.Precedence
}
func (l PDRConfList) Swap(i, j int) { l.PdrList[i], l.PdrList[j] = l.PdrList[j], l.PdrList[i] }
