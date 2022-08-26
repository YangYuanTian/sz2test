package metrics

import (
	"net"
	"upf/internal/pkg/cmn/metric"
)

// upf 统计指标 counter
const (
	// forward
	totalPackets          string = "Total Packets"
	totalBits             string = "Total Bits"
	totalDiscardedPackets string = "Total Discarded Packets"

	// up link
	upLinkTotalPacketsSent     string = "UpLink Total Packets Sent"
	upLinkTotalPacketsReceived string = "UpLink Total Packets Received"

	upLinkTotalBitsSent                 string = "UpLink Total Bits Sent"
	upLinkTotalBitsReceived             string = "UpLink Total Bits Received"
	upLinkTotalReceivedPacketsDiscarded string = "UpLink Total Received Packets Discarded"
	upLinkTotalSentPacketsDiscarded     string = "UpLink Total Sent Packets Discarded"
	upLinkTotalInvalidPackets           string = "UpLink Total Invalid Packets"
	upLinkTotalDiscardedPackets         string = "UpLink Total Discarded Packets"

	// down link
	downLinkTotalPacketsSent     string = "DownLink Total Packets Sent"
	downLinkTotalPacketsReceived string = "DownLink Total Packets Received"

	downLinkTotalBitsSent                 string = "DownLink Total Bits Sent"
	downLinkTotalBitsReceived             string = "DownLink Total Bits Received"
	downLinkTotalReceivedPacketsDiscarded string = "DownLink Total Received Packets Discarded"
	downLinkTotalSentPacketsDiscarded     string = "DownLink Total Sent Packets Discarded"
	downLinkTotalInvalidPackets           string = "DownLink Total Invalid Packets"
	downLinkTotalDiscardedPackets         string = "DownLink Total Discarded Packets"

	// pfcp node
	pfcpAssociationSetupRequestTotalReceived string = "PFCP Association Setup Request Total Received"
	pfcpAssociationSetupResponseTotalSent    string = "PFCP Association Setup Response Total Sent"

	heartBeatRequestTotalReceived  string = "HeartBeat Request Total Received"
	heartBeatResponseTotalSent     string = "HeartBeat Response Total Sent"
	heartBeatResponseTotalReceived string = "HeartBeat Response Total Received"
	heartBeatRequestTotalSent      string = "HeartBeat Request Total Sent"

	pfcpAssociationUpdateRequestTotalReceived  string = "PFCP Association Update Request Total Received"
	pfcpAssociationUpdateResponseTotalSent     string = "PFCP Association Update Response Total Sent"
	pfcpAssociationUpdateResponseTotalReceived string = "PFCP Association Update Response Total Received"
	pfcpAssociationUpdateRequestTotalSent      string = "PFCP Association Update Request Total Sent"

	pfcpNodeReportRequestTotalSent      string = "PFCP NodeReport Request Total Received"
	pfcpNodeReportResponseTotalReceived string = "PFCP NodeReport Request Total Received"

	pfcpAssociationReleaseRequestTotalReceived string = "PFCP Association Release Request Total Received"
	pfcpAssociationReleaseResponseTotalSent    string = "PFCP Association Release Response TotalSent"

	pfcpPFDManagementRequestTotalReceived string = "PFCP PFDManagement Request Total Received"
	pfcpPFDManagementRequestTotalSent     string = "PFCP PFDManagement Request Total Sent"

	//pfcp session
	pfcpSessionEstablishmentRequestTotalReceived string = "PFCP Session Establishment Request Total Received"
	pfcpSessionEstablishmentResponseTotalSent    string = "PFCP Session Establishment Response Total Sent"

	pfcpSessionModificationRequestTotalReceived string = "PFCP Session Modification Request Total Received"
	pfcpSessionModificationResponseTotalSent    string = "PFCP Session Modification Response Total Sent"

	pfcpSessionDeletionRequestTotalReceived string = "PFCP Session Deletion Request Total Received"
	pfcpSessionDeletionResponseTotalSent    string = "PFCP Session Deletion Response Total Sent"

	pfcpSessionReportRequestTotalSent      string = "PFCP Session Report Request Total Sent"
	pfcpSessionReportResponseTotalReceived string = "PFCP Session Report Response Total Received"

	//N3
	echoRequest      string = "Echo Request"
	echoResponse     string = "Echo Response"
	endMarksMessages string = "End Marks Messages"
)

// Session 统计
// UpfSessionMetrics const
const (
	UpLinkSessionReceivedPacket   string = "UpLink Session Received Packet"
	UpLinkSessionSendPacket       string = "UpLink Session Send Packet"
	DownLinkSessionReceivedPacket string = "DownLink Session Received Packet"
	DownLinkSessionSendPacket     string = "DownLink Session Send Packet"

	UpLinkSessionBitsReceived      = "UpLink Session Bits Received"
	UpLinkSessionBitsSent          = "UpLink Session Bits Sent"
	UpLinkSessionBitsReceivedPre   = "UpLink Session Bits Received Previous"
	DownLinkSessionBitsReceived    = "DownLink Session Bits Received"
	DownLinkSessionBitsSent        = "DownLink Session Bits Sent"
	DownLinkSessionBitsReceivedPre = "DownLink Session Bits Received Previous"

	DownLinkSessionPacketsDiscarded = "DownLink Session Packets Discarded"
	UpLinkSessionPacketsDiscarded   = "UpLink Session Packets Discarded"

	// 当前及时值
	UpfSessionID                                  = "Upf Session ID"
	DownLinkSessionRuleID                         = "DownLink Session Rule ID"
	DownLinkSessionUEIPAddress                    = "DownLink Session UE IP Address"
	DownLinkSessionQoSFlowID                      = "DownLink Session QoS Flow ID"
	DownLinkSessionFlowDescription                = "DownLink Session Flow Description"
	DownLinkSessionForwardingAction               = "DownLink Session Forwarding Action"
	DownLinkSessionOuterHeaderCreationTEID        = "DownLink Session Outer Header Creation TEID"
	DownLinkSessionOuterHeaderCreationIPv4Address = "DownLink Session Outer Header Creation IPv4 Address"

	UpLinkSessionRuleID                        = "UpLink Session Rule ID"
	UpLinkSessionTrafficEndpointID             = "UpLink Session Traffic Endpoint ID"
	UpLinkSessionQoSFlowID                     = "UpLink Session QoS Flow ID"
	UpLinkSessionOuterHeaderRemovalDescription = "UpLink Session Outer Header Removal Description"
	UpLinkSessionForwardingAction              = "UpLink Session Forwarding Action"
	UpLinkSessionNetworkInstance               = "UpLink Session Network Instance"
	UpLinkSessionDNGatewayIPAddress            = "UpLink Session DN Gateway IP Address"

	//应用层协议数据计数
	UpLinkSessionDNSBitReceived  = "UpLink Session DNS Bit Received"
	UpLinkSessionFTPBitReceived  = "UpLink Session FTP Bit Received"
	UpLinkSessionRTSPBitReceived = "UpLink Session RTSP Bit Received"
	UpLinkSessionMQTTBitReceived = "UpLink Session MQTT Bit Received"
	UpLinkSessionHTTPBitReceived = "UpLink Session HTTP Bit Received"

	DownLinkSessionDNSBitReceived  = "DownLink Session DNS Bit Received"
	DownLinkSessionFTPBitReceived  = "DownLink Session FTP Bit Received"
	DownLinkSessionRTSPBitReceived = "DownLink Session RTSP Bit Received"
	DownLinkSessionMQTTBitReceived = "DownLink Session MQTT Bit Received"
	DownLinkSessionHTTPBitReceived = "DownLink Session HTTP Bit Received"

	//记录上次报告时间
	LastSessionReportTime  = "Last Session Report Time Record"
	FirstSessionReportTime = "First Session Report Time Record"
	NowSessionDataTime     = "Now Session Data Time Record"
	SetupSessiontime       = "Setup Session Time"
	LastSessionReportpkt   = "Last Session Report pkt num Record"

	//记录上报门限值
	UpLinkSessionBitsReceivedSub   = "UpLink Session Trigger Threshold"
	DownLinkSessionBitsReceivedSub = "DownLink Session Trigger Threshold"

	//记录上报序号
	URSEQN = "Record and Report Sequence"
)

// 用于初始化
var UpfSessionMetricsCounter = []string{
	UpLinkSessionReceivedPacket,
	UpLinkSessionSendPacket,
	DownLinkSessionReceivedPacket,
	DownLinkSessionSendPacket,

	UpLinkSessionBitsReceived,
	UpLinkSessionBitsSent,
	UpLinkSessionBitsReceivedPre,
	DownLinkSessionBitsReceived,
	DownLinkSessionBitsSent,
	DownLinkSessionBitsReceivedPre,

	DownLinkSessionPacketsDiscarded,
	UpLinkSessionPacketsDiscarded,
	// 当前及时值
	UpfSessionID,
	DownLinkSessionRuleID,
	DownLinkSessionUEIPAddress,
	DownLinkSessionQoSFlowID,
	DownLinkSessionFlowDescription,
	DownLinkSessionForwardingAction,
	DownLinkSessionOuterHeaderCreationTEID,
	DownLinkSessionOuterHeaderCreationIPv4Address,

	UpLinkSessionRuleID,
	UpLinkSessionTrafficEndpointID,
	UpLinkSessionQoSFlowID,
	UpLinkSessionOuterHeaderRemovalDescription,
	UpLinkSessionForwardingAction,
	UpLinkSessionNetworkInstance,
	UpLinkSessionDNGatewayIPAddress,

	UpLinkSessionDNSBitReceived,
	UpLinkSessionFTPBitReceived,
	UpLinkSessionRTSPBitReceived,
	UpLinkSessionMQTTBitReceived,
	UpLinkSessionHTTPBitReceived,

	DownLinkSessionDNSBitReceived,
	DownLinkSessionFTPBitReceived,
	DownLinkSessionRTSPBitReceived,
	DownLinkSessionMQTTBitReceived,
	DownLinkSessionHTTPBitReceived,

	LastSessionReportTime,
	FirstSessionReportTime,
	NowSessionDataTime,
	SetupSessiontime,
	LastSessionReportpkt,

	UpLinkSessionBitsReceivedSub,
	DownLinkSessionBitsReceivedSub,

	URSEQN,
}

type UpfSessionInfo struct {
	UpfSessionID                                  uint64 `json:"upf_session_id"`
	DownLinkSessionRuleID                         uint16 `json:"down_link_pdr_id"`
	DownLinkSessionUEIPAddress                    net.IP `json:"down_link_ue_ip_address,omitempty"`
	DownLinkSessionQoSFlowID                      uint8  `json:"down_link_qfi"`
	DownLinkSessionFlowDescription                string `json:"down_link_flow_description"`
	DownLinkSessionForwardingAction               uint8  `json:"down_link_forwarding_action"`
	DownLinkSessionOuterHeaderCreationTEID        string `json:"down_link_gnb_teid"`
	DownLinkSessionOuterHeaderCreationIPv4Address net.IP `json:"down_link_gnb_ipv4_address,omitempty"`

	UpLinkSessionRuleID                        uint16 `json:"up_link_pdr_id"`
	UpLinkSessionTrafficEndpointID             string `json:"up_link_upf_teid"`
	UpLinkSessionQoSFlowID                     uint8  `json:"up_link_qfi"`
	UpLinkSessionFlowDescription               string `json:"up_link_flow_description"`
	UpLinkSessionOuterHeaderRemovalDescription uint8  `json:"up_link_gtp_header_description"`
	UpLinkSessionForwardingAction              uint8  `json:"up_link_forwarding_action"`
	UpLinkSessionNetworkInstance               string `json:"up_link_network_instance"`
	UpLinkSessionDNGatewayIPAddress            net.IP `json:"up_link_network_instance_ip_address,omitempty"`
}

// upf module 统计指标全局变量
type UpfModule struct {
	// forward
	TotalPackets                  metric.Counter
	TotalPacketsPrevious          int64
	TotalBits                     metric.Counter
	TotalBitsPrevious             int64
	TotalDiscardedPackets         metric.Counter
	TotalDiscardedPacketsPrevious int64

	// uplink
	UpLinkTotalPacketsSent             metric.Counter
	UpLinkTotalPacketsSentPrevious     int64
	UpLinkTotalPacketsReceived         metric.Counter
	UpLinkTotalPacketsReceivedPrevious int64

	UpLinkTotalBitsSent             metric.Counter
	UpLinkTotalBitsSentPrevious     int64
	UpLinkTotalBitsReceived         metric.Counter
	UpLinkTotalBitsReceivedPrevious int64

	UpLinkTotalReceivedPacketsDiscarded metric.Counter
	UpLinkTotalSentPacketsDiscarded     metric.Counter
	UpLinkTotalInvalidPackets           metric.Counter
	UpLinkTotalDiscardedPackets         metric.Counter

	// downlink
	DownLinkTotalPacketsSent             metric.Counter
	DownLinkTotalPacketsSentPrevious     int64
	DownLinkTotalPacketsReceived         metric.Counter
	DownLinkTotalPacketsReceivedPrevious int64

	DownLinkTotalBitsSent             metric.Counter
	DownLinkTotalBitsSentPrevious     int64
	DownLinkTotalBitsReceived         metric.Counter
	DownLinkTotalBitsReceivedPrevious int64

	DownLinkTotalReceivedPacketsDiscarded metric.Counter
	DownLinkTotalSentPacketsDiscarded     metric.Counter
	DownLinkTotalInvalidPackets           metric.Counter
	DownLinkTotalDiscardedPackets         metric.Counter

	//pfcp node
	PFCPAssociationSetupRequestTotalReceived         metric.Counter
	PFCPAssociationSetupRequestTotalReceivedPrevious int64
	PFCPAssociationSetupResponseTotalSent            metric.Counter
	PFCPAssociationSetupResponseTotalSentPrevious    int64

	HeartBeatRequestTotalReceived          metric.Counter
	HeartBeatRequestTotalReceivedPrevious  int64
	HeartBeatResponseTotalSent             metric.Counter
	HeartBeatResponseTotalSentPrevious     int64
	HeartBeatResponseTotalReceived         metric.Counter
	HeartBeatResponseTotalReceivedPrevious int64
	HeartBeatRequestTotalSent              metric.Counter
	HeartBeatRequestTotalSentPrevious      int64

	PFCPAssociationUpdateRequestTotalReceived          metric.Counter
	PFCPAssociationUpdateRequestTotalReceivedPrevious  int64
	PFCPAssociationUpdateResponseTotalSent             metric.Counter
	PFCPAssociationUpdateResponseTotalSentPrevious     int64
	PFCPAssociationUpdateResponseTotalReceived         metric.Counter
	PFCPAssociationUpdateResponseTotalReceivedPrevious int64
	PFCPAssociationUpdateRequestTotalSent              metric.Counter
	PFCPAssociationUpdateRequestTotalSentPrevious      int64

	PFCPNodeReportRequestTotalSent              metric.Counter
	PFCPNodeReportRequestTotalSentPrevious      int64
	PFCPNodeReportResponseTotalReceived         metric.Counter
	PFCPNodeReportResponseTotalReceivedPrevious int64

	PFCPAssociationReleaseRequestTotalReceived         metric.Counter
	PFCPAssociationReleaseRequestTotalReceivedPrevious int64
	PFCPAssociationReleaseResponseTotalSent            metric.Counter
	PFCPAssociationReleaseResponseTotalSentPrevious    int64

	PFCPPFDManagementRequestTotalReceived         metric.Counter
	PFCPPFDManagementRequestTotalReceivedPrevious int64
	PFCPPFDManagementResponseTotalSent            metric.Counter
	PFCPPFDManagementResponseTotalSentPrevious    int64

	// pfcp session
	PFCPSessionEstablishmentRequestTotalReceived         metric.Counter
	PFCPSessionEstablishmentRequestTotalReceivedPrevious int64
	PFCPSessionEstablishmentResponseTotalSent            metric.Counter
	PFCPSessionEstablishmentResponseTotalSentPrevious    int64

	PFCPSessionModificationRequestTotalReceived         metric.Counter
	PFCPSessionModificationRequestTotalReceivedPrevious int64
	PFCPSessionModificationResponseTotalSent            metric.Counter
	PFCPSessionModificationResponseTotalSentPrevious    int64

	PFCPSessionDeletionRequestTotalReceived         metric.Counter
	PFCPSessionDeletionRequestTotalReceivedPrevious int64
	PFCPSessionDeletionResponseTotalSent            metric.Counter
	PFCPSessionDeletionResponseTotalSentPrevious    int64

	PFCPSessionReportRequestTotalSent              metric.Counter
	PFCPSessionReportRequestTotalSentPrevious      int64
	PFCPSessionReportResponseTotalReceived         metric.Counter
	PFCPSessionReportResponseTotalReceivedPrevious int64

	//N3
	EchoRequest              metric.Counter
	EchoRequestPrevious      int64
	EchoResponse             metric.Counter
	EchoResponsePrevious     int64
	EndMarksMessages         metric.Counter
	EndMarksMessagesPrevious int64
}
