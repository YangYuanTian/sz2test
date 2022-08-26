package pdr

import (
	"fmt"
	"lite5gc/cmn/message/pfcp"
	"lite5gc/cmn/nas/nasie"
	"lite5gc/cmn/types3gpp"
	"net"
	"strconv"
)

// 23.501 中的upf pdr 的要求

// 3GPP TS 23.501 V15.3.0 (2018-09)
// 5.7	QoS model
type QoSModel struct {
}

// 5.7.1.1	QoS Flow
type QoSFlow struct {
	QFI uint8 // QoS Flow ID
	// Resource Type
	QoSFlowType nasie.QosResourceType
}

// Reflective QoS
type ReflectiveQoS struct {
	RQI bool
}

// 5.7.1.5
// QoS Flow mapping
type QoSFlowMapping struct {
	//QoS profile to the (R)AN
	QosProfile
	//QoS rule(s) to the UE
	QoSRules
	//PDR(s) to the UPF
	PDRs
}

// QoS profile to the (R)AN
type QosProfile struct {
	QoSFlow
	QosProfile nasie.QosProfile
	optionally QosProfileOption
}
type QosProfileOption struct {
	DSCP string
}

// QoS rule(s) to the UE
type QoSRules struct {
	QoSRules nasie.QoSRules
}

// PDR(s) to the UPF
type PDRs struct {
	DlPdr DLPDR
	UlPdr ULPDR
}

// DL PDR
type DLPDR struct {
	PDR
	// the Reflective QoS Indication
	ReflectiveQoS
}
type ULPDR struct {
	PDR
}
type PDR struct {
	// packet marking information
	QFI        pfcp.IEQFI
	Precedence pfcp.IEPrecedence
	// QoS related information
	QoSParameters pfcp.IECreateQER
	// Packet Filter Set
	PacketFilterSet
}

//type QosParameters struct {
//	nasie.ParametersIE
//}

//Table 5.7.4-1: Standardized 5QI to QoS characteristics mapping
//type QoScharacteristicsmapping struct {
//	//5QI Value, key
//	QI5 nasie.QI5Contents
//	//Resource Type
//	//Default Priority Level
//	//Packet Delay Budget
//	//Packet Error Rate
//	//Default Maximum Data Burst Volume
//	//Default Averaging Window
//	nasie.Dynamic5Qi
//	//Example Services
//}

// 5.7.6	Packet Filter Set
// PacketFilterLists
type PacketFilterSet struct {
	IpPacketFilterSet  []IpPacketFilterSetTmp
	EthPacketFilterSet []EthPacketFilterSet
}

func (this *PacketFilterSet) String() string {
	s := ""
	for i, v := range this.IpPacketFilterSet {
		s += fmt.Sprintf("IpPacketFilterSet %d:%+v", i, v)
	}
	for i, v := range this.EthPacketFilterSet {
		s += fmt.Sprintf("EthPacketFilterSet %d:%+v", i, v)
	}
	return s
}

//IP Packet Filter Set
/*-	Source/destination IP address or IPv6 prefix.
-	Source / destination port number.
-	Protocol ID of the protocol above IP/Next header type.
-	Type of Service (TOS) (IPv4) / Traffic class (IPv6) and Mask.
-	Flow Label (IPv6).
-	Security parameter index.
-	Packet Filter direction.*/
type IpPacketFilterSet struct {
	//pfcp.IECreateFAR
	SrcIp                  net.IP
	SrcPort                int
	DstIp                  net.IP
	DstPort                int
	Protocol               IPProtocol
	ToSTrafficClass        uint16 // ipv4 TOS //ipv6 Traffic class
	FlowLabel              uint32 // ipv6
	SecurityParameterIndex uint32 //types3gpp.SecurityIndication
	Direction              nasie.PacketFilterDirection
}

// 保存配置规则的解析结果  IPNet 格式
type IpPacketFilterSetTmp struct {
	SrcIp                  net.IPNet // ip/mask
	SrcPort                PortRange //port-port
	DstIp                  net.IPNet
	DstPort                PortRange
	Protocol               IPProtocol
	ToSTrafficClass        uint16 // ipv4 TOS //ipv6 Traffic class
	FlowLabel              uint32 // ipv6
	SecurityParameterIndex uint32 //types3gpp.SecurityIndication
	Direction              nasie.PacketFilterDirection
}

type PortRange struct {
	MinPort int
	MaxPort int
}

func (p PortRange) String() string {

	if p.MaxPort == p.MinPort {
		return strconv.Itoa(p.MinPort)
	}
	return strconv.Itoa(p.MinPort) + "-" + strconv.Itoa(p.MaxPort)
}

// 5.7.6.3	Ethernet Packet Filter Set
/*-	Source/destination MAC address
-	Ethertype as defined in IEEE 802.3 [yy]
-	Customer-VLAN tag (C-TAG) and/or Service-VLAN tag (S-TAG) VID fields as defined in IEEE 802.1Q
-	Customer-VLAN tag (C-TAG) and/or Service-VLAN tag (S-TAG) PCP/DEI fields as defined in IEEE 802.1Q
-	IP Packet Filter Set, in the case that Ethertype indicates IPv4/IPv6 payload.
-	Packet Filter direction.*/

type EthPacketFilterSet struct {
	SrcMac            net.HardwareAddr
	DstMac            net.HardwareAddr
	EthType           uint16
	VID               int // 802.1ad Ethernet Type allocations
	PCP               byte
	DEI               byte
	IpPacketFilterSet IpPacketFilterSet
	Direction         nasie.PacketFilterDirection
}

/*UPF traffic detection capabilities may be used by the SMF in order to control at least following features of the UPF:
-	##Traffic detection (e.g. classifying traffic of IP type, Ethernet type, or unstructured type)
-	Traffic reporting (e.g. allowing SMF support for charging).
-	##QoS enforcement (The corresponding requirements are defined in clause 5.7).
-	Traffic routing (e.g. as defined in clause 5.6.4. for UL CL or IPv6 multi-homing).*/

// QoS traffic 处理规则

//5.7.1.6 DL traffic
// - UPF maps User Plane traffic to QoS Flows based on the PDRs.

//-	UPF performs Session-AMBR enforcement and counting of packets for charging.

//-	UPF transmits the PDUs of the PDU Session in a single tunnel between 5GC and (R)AN,
// the UPF includes the QFI in the encapsulation header. In addition, UPF may include an
// indication for Reflective QoS activation in the encapsulation header.

//-	UPF performs transport level packet marking in DL, e.g. setting the DiffServ Code point
// in outer IP header. Transport level packet marking may be based on the 5QI and ARP of the associated QoS Flow.

//5.7.1.7 UL Traffic
//-	UPF verifies whether QFIs in the UL PDUs are aligned with the QoS Rules
// provided to the UE or implicitly derived by the UE in the case of Reflective QoS).

//-	UPF and UE perform Session-AMBR enforcement and the UPF performs counting of packets for charging.

//5.7.1.8 AMBR/MFBR enforcement and rate limitation
//the DL Session-AMBR shall be enforced separately in every UPF that terminates the N6 interface
//The MFBR is enforced in the UPF in the Downlink for GFBR QoS Flows.

// 5.7.1.9 Precedence Value
// QoS规则或PDR的评估按其优先级值的递增顺序执行。（0~255,0的优先级高）

// UPF
// 5.8.2.4	Traffic Detection
//For IP PDU Session type
/*-	CN tunnel info.
-	Network instance.
-	QFI.
-	IP Packet Filter Set as defined in clause 5.7.6.2.
-	Application Identifier: The Application ID is an index to a set of application detection rules configured in UPF.*/
type CNTunnelInfo struct {
	TEID      types3gpp.Teid
	UpfIpAddr net.IP
}
type IpTrafficDetectionInfo struct {
	CNTunnelInfo
	NetworkInstance   types3gpp.Apn // different IP domains or overlapping IP addresses
	QFI               uint8
	IpPacketFilterSet IpPacketFilterSet
	AppId             string
}

// For Ethernet PDU Session type
/*-	CN tunnel info.
-	Network instance.
-	QFI.
-	Ethernet Packet Filter Set as defined in clause 5.7.6.3.*/
type EthTrafficDetectionInfo struct {
	CNTunnelInfo
	NetworkInstance    types3gpp.Apn
	QFI                uint8
	EthPacketFilterSet EthPacketFilterSet
}

// set of application detection rules configured in UPF
// App ID 与 目的ip/port 的映射关系，key：AppID,value:ip/port
type ApptoPortMap struct {
	AppId string
	port  int
	Ip    net.IP
}

// 5.8.2.5	Control of User Plane Forwarding
/*The following forwarding functionality is required by the UPF:
-	##Apply N3 /N9 tunnel related handling, i.e. encapsulation.
-	Forward the traffic to/from the SMF, e.g. as described in Table 5.8.2.5-1).
-	Forward the SM PDU DN Request Container from SMF to DN-AAA server
-	##Forward the traffic according to locally configured policy for traffic steering.*/
// todo: acting as PSA
type FAR struct {
	pfcp.IECreateFAR
}

// todo 5.8.2.6	Charging and Usage Monitoring Handling

// 5.8.2.7	PDU Session and QoS Flow Policing
//
//	Non-GFBR QoS Flows
type SessionAMBR struct {
	types3gpp.Ambr
}

// GFBR QoS Flow
type GBRQoSFlow struct {
	//types3gpp.GBRQosInfo
	types3gpp.GBRQosInfo
	AverageWindow uint
}

// 5.8.2.8	PCC Related Functions
// SMF : A predefined PCC rule is configured in the SMF. The traffic detection filters
// todo
// UPF: the application detection filter identified by an application identifier
// todo
//5.8.2.8.1	Activation/Deactivation of predefined PCC rules
// todo 构造对应PDR处理表

//5.8.2.8.2	Enforcement of Dynamic PCC Rules
// 统一在SMF配置

//5.8.2.8.3	Redirection
//todo

//5.8.2.8.4	Support of PFD Management
// todo 动态更新App ID 对应的规则

//5.8.3.2	Buffering at UPF
/*The SMF provides instructions to the UPF for at least the following behaviours:
-	buffer without reporting the arrival of first downlink packet,
-	buffer with reporting the arrival of first downlink packet, or
-	drop packet.*/
