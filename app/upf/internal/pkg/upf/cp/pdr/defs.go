package pdr

import (
	"encoding/json"
	"fmt"
	"net"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/nas/nasie"
	"upf/internal/pkg/cmn/rlogger"
)

const moduleTag rlogger.ModuleTag = "pdr"

var FuncEntry = rlogger.FuncEntry

// 29.244 中pdr的定义

// 23.501 中对N4参考的要求
//5.8.2.11 Parameters for N4 session management

/*-	Packet Detection Rules (PDR) that contain information to classify traffic (PDU(s)) arriving at the UPF;
-	Forwarding Action Rules (FAR) that contain information on whether forwarding, dropping or buffering is
to be applied to a traffic identified by PDR(s);
-	Usage Reporting Rules (URR) contains information that defines how traffic identified by PDR(s) shall
be accounted as well as how a certain measurement shall be reported;
-	QoS Enforcement Rules (QER), that contain information related to QoS enforcement of traffic identified by PDR(s);
-	Trace Requirements.*/

// PDR
// 5.8.2.11.3	Packet Detection Rule
type PacketDetectionRule struct {
	//N4 Session ID
	SEID uint64
	//Rule ID
	RuleID uint16
	//Precedence
	Precedence uint32
	PDI        PacketDetectionInfo
	//Outer header removal
	OuterHeaderRemoval uint8
	//Forwarding Action Rule ID
	//pfcp.IECreatePDR
	FarI FarInfo
	//List of Usage Reporting Rule(s)
	UrrI []UrrInfo

	//List of QoS Enforcement Rule(s)
	QerI []QerInfo
}

func (this *PacketDetectionRule) String() string {
	s := fmt.Sprintf("SEID:%d,", this.SEID)
	s += fmt.Sprintf("RuleID:%d,", this.RuleID)
	s += fmt.Sprintf("Precedence:%d,", this.Precedence)
	s += fmt.Sprintf("PDI:%s,", &this.PDI)
	s += fmt.Sprintf("OuterHeaderRemoval:%d,", this.OuterHeaderRemoval)
	s += fmt.Sprintf("FarI:%s,", &this.FarI)
	for i, v := range this.UrrI {
		s += fmt.Sprintf("UrrI %d:%s,", i, &v)
	}
	for i, v := range this.QerI {
		s += fmt.Sprintf("QerI %d:%s,", i, &v)
	}
	return s
}

// Packet detection information
type PacketDetectionInfo struct {
	//Source interface
	SourceInterface nasie.PacketFilterDirection
	//UE IP address
	UEIPAddress net.IP
	//Network instance
	NetworkInstance string //types3gpp.Apn
	//CN tunnel info
	CNTunnelInfo
	//Packet Filter Set
	PacketFilterSet PacketFilterSet
	//Application ID
	AppId string
	//QoS Flow ID
	QFI uint8
	//Ethernet PDU Session Information
	ETHI uint8 //pfcp.IEEthernetPDUSessionInfo
}

func (this *PacketDetectionInfo) String() string {
	s := fmt.Sprintf("SourceInterface:%d,", this.SourceInterface)
	s += fmt.Sprintf("UEIPAddress:%s,", this.UEIPAddress)
	s += fmt.Sprintf("NetworkInstance:%s,", this.NetworkInstance)
	s += fmt.Sprintf("CNTunnelInfo:(TEID:%d,UPFIP:%s),", this.TEID, this.UpfIpAddr)
	s += fmt.Sprintf("PacketFilterSet:%s,", &this.PacketFilterSet)
	s += fmt.Sprintf("AppId:%s,", this.AppId)
	s += fmt.Sprintf("QFI:%d,", this.QFI)
	s += fmt.Sprintf("ETHI:%d,", this.ETHI)
	return s
}

// Forwarding Action Rule
type FarInfo struct {
	FarID uint32
	Far   *ForwardActionRule
}

func (this *FarInfo) String() string {
	return fmt.Sprintf("FarID %d:%s", this.FarID, this.Far)
}

// List of Usage Reporting Rule(s)
type UrrInfo struct {
	UrrID uint32
	Urr   *pfcp.IECreateURR
}

func (this *UrrInfo) String() string {
	return fmt.Sprintf("%+v", *this)
}

// List of QoS Enforcement Rule(s)
type QerInfo struct {
	QerID uint32
	Qer   *QoSEnforcementRule
}

func (q *QerInfo) String() string {
	return fmt.Sprintf("%+v", *q)
}

// QER
// 5.8.2.11.4	QoS Enforcement Rule
type QoSEnforcementRule struct {
	//N4 Session ID
	//SEID uint64
	//Rule ID
	RuleID uint32
	//QoS Enforcement Rule correlation ID， only used for interworking with EPC.
	QERcorrelationID int
	//Gate status UL/DL,Values are: open, close
	ULGateStatus GateStatusT
	DLGateStatus GateStatusT
	//nasie.ParametersIE
	//Maximum bitrate
	MBR *pfcp.IEMBR
	//Guaranteed bitrate
	//GBRQoSFlow
	GBR *pfcp.IEGBR
	//Averaging window
	AverageWindow uint
	//Down-link flow level marking ,For UPF, this is for controlling the setting of the RQI in the encapsulation header.
	DLFlowLevelMarking ReflectiveQoS

	//QoS Flow ID //g40
	QosFlowId QoSFlow
	//Paging Policy Indicator//g40
	PPI uint8

	//Packet rate，only used for interworking with EPC.
	PacketRate uint64
}

// Gate status UL/DL,Values are: open, close
type GateStatusT byte

const (
	Open  GateStatusT = 0
	Close GateStatusT = 1
)

//Maximum bitrate
/*-	APN-AMBR (for a QER that is referenced by all relevant Packet Detection Rules of all PDN Connections to an APN) (NOTE 1).
-	Session-AMBR (for a QER that is referenced by all relevant Packet Detection Rules of the PDU Session)
-	QoS Flow MFBR (for a QER that is referenced by all Packet Detection Rules of a QoS Flow)
-	SDF MFBR (for a QER that is referenced by the uplink/downlink Packet Detection Rule of a SDF)
-	Bearer MFBR (for a QER that is referenced by all relevant Packet Detection Rules of a bearer) (NOTE 1).
NOTE 1: only used for interworking with EPC
*/
type MaximumBitrateT byte

const (
	APN_AMBR     MaximumBitrateT = 0
	ession_AMBR  MaximumBitrateT = 1
	QoS_Flow_MBR MaximumBitrateT = 2
	SDF_MBR      MaximumBitrateT = 3
	Bearer_MBR   MaximumBitrateT = 4
)

//Guaranteed bitrate
/*This field contains:
-	QoS Flow GFBR (for a QER that is referenced by all Packet Detection Rules of a QoS Flow)
-	Bearer GFBR (for a QER that is referenced by all relevant Packet Detection Rules of a bearer) (NOTE 1).
NOTE 1: only used for interworking with EPC*/
type GuaranteedBitrateT byte

const (
	QoSFlow_GBR GuaranteedBitrateT = 0
	Bearer_GBR  GuaranteedBitrateT = 1
)

// URR
//5.8.2.11.5	Usage Reporting Rule todo

// FAR
// 5.8.2.11.6	Forwarding Action Rule
type ForwardActionRule struct {
	//N4 Session ID
	//SEID uint64
	//Rule ID
	RuleID uint32
	//Action
	Action ActionT //pfcp.IEApplyAction
	//Network instance//(NOTE 2)
	NetworkInstance string //*types3gpp.Apn
	//Destination interface//(NOTE 3)
	DstInterface DestinationInterfaceT //pfcp.IEDestinationInterface
	//Outer header creation//(NOTE 3)
	OuterHeaderCreation *pfcp.IEOuterHeaderCreation

	//Send end marker packet(s)//(NOTE 2)
	SendEndMarker byte
	//Transport level marking//(NOTE 3)
	//pfcp.IETransportLevelMarking
	ToSTrafficClass uint16
	//Forwarding policy//(NOTE 3)
	//pfcp.IEForwardingPolicy
	ForwardingPolicy string
	//Request for Proxying in UPF , ARP proxying
	//pfcp.IEProxying
	Proxying uint8
	//Container for header enrichment//(NOTE 2) ,Only relevant for the uplink direction.
	HeaderEnrichment *pfcp.IEHeaderEnrichment
	//Buffering Action Rule//(NOTE 5)
	BAR *pfcp.IECreateBAR
}

func (far *ForwardActionRule) String() string {
	s := fmt.Sprintf("RuleID:%d,", far.RuleID)
	s += fmt.Sprintf("Action:%s,", far.Action)
	s += fmt.Sprintf("NetworkInstance:%s,", far.NetworkInstance)
	s += fmt.Sprintf("DstInterface:%s,", far.DstInterface)
	tmp, _ := json.Marshal(far.OuterHeaderCreation)
	s += fmt.Sprintf("OuterHeaderCreation:%s,", tmp)
	s += fmt.Sprintf("SendEndMarker:%d,", far.SendEndMarker)
	s += fmt.Sprintf("ToSTrafficClass:%d,", far.ToSTrafficClass)
	s += fmt.Sprintf("ForwardingPolicy:%s,", far.ForwardingPolicy)
	s += fmt.Sprintf("Proxying:%d,", far.Proxying)
	tmp, _ = json.Marshal(far.HeaderEnrichment)
	s += fmt.Sprintf("HeaderEnrichment:%s,", tmp)
	tmp, _ = json.Marshal(far.BAR)
	s += fmt.Sprintf("BAR:%s,", tmp)
	return s
}

// Action
// forwarded, duplicated, dropped or buffered.
type ActionT byte

func (a ActionT) String() string {
	switch a {
	case FORW:
		return fmt.Sprintf("%d:forward", a)
	case DUPL:
		return fmt.Sprintf("%d:duplicat", a)
	case DROP:
		return fmt.Sprintf("%d:dropped", a)
	case BUFF:
		return fmt.Sprintf("%d:buffered", a)
	case NOCP:
		return fmt.Sprintf("%d:Notify the CP function", a)
	default:
		return fmt.Sprintf("%d:null", a)

	}

}

const (
	//forwarded
	FORW ActionT = pfcp.IeFlagBit2
	//duplicated
	DUPL ActionT = pfcp.IeFlagBit5
	//dropped
	DROP ActionT = pfcp.IeFlagBit1
	//buffered
	BUFF ActionT = pfcp.IeFlagBit3
	// Notify the CP function
	NOCP ActionT = pfcp.IeFlagBit4
)

const NOCPBUFF ActionT = pfcp.IeFlagBit4 + pfcp.IeFlagBit3

// Destination interface//(NOTE 3)
// Contains the values "access side", "core side", "SMF" or "N6-LAN".
type DestinationInterfaceT byte

func (d DestinationInterfaceT) String() string {
	return fmt.Sprintf("%d", d)
}

const (
	DestinationInterface_Access          DestinationInterfaceT = 0
	DestinationInterface_Core            DestinationInterfaceT = 1
	DestinationInterface_SGiLAN_or_N6LAN DestinationInterfaceT = 2
	DestinationInterface_CPFunction      DestinationInterfaceT = 3
	DestinationInterface_LIFunction      DestinationInterfaceT = 4
)

//5.8.2.11.7	Usage Report generated by UPF todo

//5.8.3	Explicit Buffer Management
