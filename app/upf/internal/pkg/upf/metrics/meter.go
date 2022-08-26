package metrics

import "upf/internal/pkg/cmn/metric"

// upf 统计指标 meter
const (
	// forward
	totalPacketsPerSec string = "Total Packets/Sec (P-I)"
	totalBitsPerSec    string = "Total Bits/Sec (P-I)"

	// up link
	upLinkPacketsSentPerSec     string = "UpLink Packets Sent/Sec (P-I)"
	upLinkPacketsReceivedPerSec string = "UpLink Packets Received/Sec (P-I)"
	upLinkBitsSentPerSec        string = "UpLink Bits Sent/Sec (P-I)"
	upLinkBitsReceivedPerSec    string = "UpLink Bits Received/Sec (P-I)"

	// down link
	downLinkPacketsSentPerSec     string = "DownLink Packets Sent/Sec (P-I)"
	downLinkPacketsReceivedPerSec string = "DownLink Packets Received/Sec (P-I)"

	downLinkBitsSentPerSec     string = "DownLink Bits Sent/Sec (P-I)"
	downLinkBitsReceivedPerSec string = "DownLink Bits Received/Sec (P-I)"

	//pfcp node
	pfcpAssociationSetupRequestTotalReceivedPerSec string = "PFCP Association Setup Request Total Received/Sec (P-I)"
	pfcpAssociationSetupResponseTotalSentPerSec    string = "PFCP Association Setup Response Total Sent/Sec (P-I)"

	heartBeatRequestTotalReceivedPerSec  string = "HeartBeat Request Total Received/Sec (P-I)"
	heartBeatRequestTotalSentPerSec      string = "HeartBeat Request Total Sent/Sec (P-I)"
	heartBeatResponseTotalReceivedPerSec string = "HeartBeat Response Total Received/Sec (P-I)"
	heartBeatResponseTotalSentPerSec     string = "HeartBeat Response Total Sent/Sec (P-I)"

	pfcpAssociationUpdateRequestTotalReceivedPerSec  string = "PFCP Association Update Request Total Received/Sec (P-I)"
	pfcpAssociationUpdateResponseTotalSentPerSec     string = "PFCP Association Update Response Total Sent/Sec (P-I)"
	pfcpAssociationUpdateResponseTotalReceivedPerSec string = "PFCP Association Update Response Total Received/Sec (P-I)"
	pfcpAssociationUpdateRequestTotalSentPerSec      string = "PFCP Association Update Request Total Sent/Sec (P-I)"

	pfcpNodeReportRequestTotalReceivedPerSec string = "PFCP Node Report Request Total Received/Sec (P-I)"
	pfcpNodeReportResponseTotalSentPerSec    string = "PFCP NodeReport Response Total Sent/Sec (P-I)"

	pfcpAssociationReleaseRequestTotalReceivedPerSec string = "PFCP Association Release Request Total Received/Sec (P-I)"
	pfcpAssociationReleaseResponseTotalSentPerSec    string = "PFCP Association Release Response Total Sent/Sec (P-I)"

	pfcpPFDManagementRequestTotalReceivedPerSec string = "PFCP PFDManagement Request Total Received/Sec (P-I)"
	pfcpPFDManagementResponseTotalSentPerSec    string = "PFCP PFDManagement Response Total Sent/Sec (P-I)"
	//pfcp session
	pfcpSessionEstablishmentRequestTotalReceivedPerSec string = "PFCP Session Establishment Request Total Received/Sec (P-I)"
	pfcpSessionEstablishmentResponseTotalSentPerSec    string = "PFCP Session Establishment Response Total Sent/Sec (P-I)"

	pfcpSessionModificationRequestTotalReceivedPerSec string = "PFCP Session Modification Request Total Received/Sec (P-I)"
	pfcpSessionModificationResponseTotalSentPerSec    string = "PFCP Session Modification Response Total Sent/Sec (P-I)"

	pfcpSessionDeletionRequestTotalReceivedPerSec string = "PFCP Session Deletion Request Total Received/Sec (P-I)"
	pfcpSessionDeletionResponseTotalSentPerSec    string = "PFCP Session Deletion Response Total Sent/Sec (P-I)"

	pfcpSessionReportRequestTotalSentPerSec      string = "PFCP Session Report Request Total Sent/Sec (P-I)"
	pfcpSessionReportResponseTotalReceivedPerSec string = "PFCP Session Report Response Total Received/Sec (P-I)"

	//N3
	echoRequestPerSec      string = "Echo Request Total Sent/Sec (P-I)"
	echoResponsePerSec     string = "Echo Response Total Received/Sec (P-I)"
	endMarksMessagesPerSec string = "End Marks Messages Total Sent/Sec (P-I)"
)

// Session 统计
// UpfSessionMetrics const
const (
	UpLinkSessionPacketsSentPerSec       string = "UpLink Session Packets Sent/Sec (P-I)"
	UpLinkSessionPacketsReceivedPerSec          = "UpLink Session Packets Received/Sec (P-I)"
	DownLinkSessionPacketsSentPerSec            = "DownLink Session Packets Sent/Sec (P-I)"
	DownLinkSessionPacketsReceivedPerSec        = "DownLink Session Packets Received/Sec (P-I)"
	UpLinkSessionBitsReceivedPerSec             = "UpLink Session Bits Received/Sec (P-I)"
	UpLinkSessionBitsSentPerSec                 = "UpLink Session Bits Sent/Sec (P-I)"
	DownLinkSessionBitsReceivedPerSec           = "DownLink Session Bits Received/Sec (P-I)"
	DownLinkSessionBitsSentPerSec               = "DownLink Session Bits Sent/Sec (P-I)"
)

// 用于初始化
var UpfSessionMetricsMeter = []string{
	UpLinkSessionPacketsSentPerSec,
	UpLinkSessionPacketsReceivedPerSec,
	DownLinkSessionPacketsSentPerSec,
	DownLinkSessionPacketsReceivedPerSec,
	UpLinkSessionBitsReceivedPerSec,
	UpLinkSessionBitsSentPerSec,
	DownLinkSessionBitsReceivedPerSec,
	DownLinkSessionBitsSentPerSec,
}

// upf module 统计指标全局变量(区间值)
type UpfModulePI struct {
	// forward
	TotalPacketsPerSec metric.Meter
	TotalBitsPerSec    metric.Meter

	// uplink
	UpLinkPacketsSentPerSec     metric.Meter
	UpLinkPacketsReceivedPerSec metric.Meter

	UpLinkBitsSentPerSec     metric.Meter
	UpLinkBitsReceivedPerSec metric.Meter

	// downlink
	DownLinkPacketsSentPerSec     metric.Meter
	DownLinkPacketsReceivedPerSec metric.Meter

	DownLinkBitsSentPerSec     metric.Meter
	DownLinkBitsReceivedPerSec metric.Meter

	// pfcp node
	PFCPAssociationSetupRequestTotalReceivedPerSec metric.Meter
	PFCPAssociationSetupResponseTotalSentPerSec    metric.Meter

	HeartBeatRequestTotalReceivedPerSec  metric.Meter
	HeartBeatRequestTotalSentPerSec      metric.Meter
	HeartBeatResponseTotalReceivedPerSec metric.Meter
	HeartBeatResponseTotalSentPerSec     metric.Meter

	PFCPAssociationUpdateRequestTotalReceivedPerSec  metric.Meter
	PFCPAssociationUpdateResponseTotalSentPerSec     metric.Meter
	PFCPAssociationUpdateResponseTotalReceivedPerSec metric.Meter
	PFCPAssociationUpdateRequestTotalSentPerSec      metric.Meter

	PFCPNodeReportRequestTotalSentPerSec      metric.Meter
	PFCPNodeReportResponseTotalReceivedPerSec metric.Meter

	PFCPAssociationReleaseRequestTotalReceivedPerSec metric.Meter
	PFCPAssociationReleaseResponseTotalSentPerSec    metric.Meter

	PFCPPFDManagementRequestTotalReceivedPerSec metric.Meter
	PFCPPFDManagementResponseTotalSentPerSec    metric.Meter

	// pfcp session
	PFCPSessionEstablishmentRequestReceivedPerSec metric.Meter
	PFCPSessionEstablishmentResponseSentPerSec    metric.Meter

	PFCPSessionModificationRequestReceivedPerSec metric.Meter
	PFCPSessionModificationResponseSentPerSec    metric.Meter

	PFCPSessionDeletionRequestReceivedPerSec metric.Meter
	PFCPSessionDeletionResponseSentPerSec    metric.Meter

	PFCPSessionReportRequestSentPerSec      metric.Meter
	PFCPSessionReportResponseReceivedPerSec metric.Meter

	//N3
	EchoRequestPerSec      metric.Meter
	EchoResponsePerSec     metric.Meter
	EndMarksMessagesPerSec metric.Meter
}
